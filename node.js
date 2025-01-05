const net = require("net");
const fs = require("fs");
const {
  encryptWithPublicKey,
  decryptWithPrivateKey,
  deriveSessionKey,
  encryptWithSessionKey,
  decryptWithSessionKey,
  generateRandomString,
  generateKeys,
} = require("./utils/crypto");

class Node {
  constructor(name, port) {
    this.name = name;
    this.port = port;
    this.serverConnections = [];
    this.clientConnections = [];
    this.serverRandom = generateRandomString();

    const keys = generateKeys();
    this.serverKey = keys.privateKey.export({ type: "pkcs1", format: "pem" });

    console.log(`[${this.name}] Requesting certificate from CA Server...`);
    this.signCertificate(
      keys.publicKey.export({ type: "pkcs1", format: "pem" }),
      name,
      (cert) => {
        if (!cert) {
          throw new Error(
            `[${this.name}] Failed to get certificate from CA Server.`
          );
        }

        this.serverCert = cert;

        fs.writeFileSync(
          `./certs/${name}-cert.pem`,
          JSON.stringify(this.serverCert)
        );
        fs.writeFileSync(`./certs/${name}-key.pem`, this.serverKey);

        console.log(`[${this.name}] Certificate received and saved.`);
      }
    );
  }

  startServer() {
    const server = net.createServer((socket) => {
      console.log(`[${this.name}] Client connected.`);

      let sessionKey;

      socket.on("data", (data) => {
        const message = JSON.parse(data.toString());
        if (message.type === "hello") {
          console.log(`[${this.name}] Received hello: ${message.clientRandom}`);

          const response = {
            type: "serverHello",
            serverRandom: this.serverRandom,
            serverCert: this.serverCert,
          };

          socket.write(JSON.stringify(response));
        } else if (message.type === "premaster") {
          const premasterSecret = decryptWithPrivateKey(
            this.serverKey,
            Buffer.from(message.encryptedPremaster, "base64")
          );

          sessionKey = deriveSessionKey(
            message.clientRandom,
            this.serverRandom,
            premasterSecret
          );

          console.log(`[${this.name}] Session key established: ${sessionKey}`);

          const secureMessage = encryptWithSessionKey(
            sessionKey,
            "serverReady"
          );
          socket.write(
            JSON.stringify({
              type: "ready",
              serverRandom: this.serverRandom,
              message: secureMessage,
            })
          );
        } else if (message.type === "clientReady") {
          const clientMessage = decryptWithSessionKey(
            sessionKey,
            message.message
          );

          if (clientMessage === "clientReady") {
            console.log(
              `[${this.name}] Client confirmed readiness. Handshake complete.`
            );
            this.serverConnections.push({
              clientAddress: socket.remoteAddress,
              clientPort: socket.remotePort,
              sessionKey,
              socket,
            });
          } else {
            console.log(`[${this.name}] Client message invalid.`);
          }
        } else if (message.type === "file") {
          const connection = this.serverConnections.find(
            (conn) => conn.clientPort === socket.remotePort
          );
          if (!connection) {
            console.log("No connection");
            return;
          }
          const decryptedFileData = decryptWithSessionKey(
            connection.sessionKey,
            message.fileData
          );
          const filePath = `./received/${message.fileName}`;
          fs.writeFileSync(filePath, decryptedFileData, "utf8");

          console.log(`[${this.name}] Received file saved as: ${filePath}`);
        }
      });

      socket.on("error", (err) => {
        console.error(`[${this.name}] Socket error:`, err.message);
      });
    });

    server.listen(this.port, () => {
      console.log(`[${this.name}] Listening on port ${this.port}`);
    });

    this.server = server;
  }

  connectToPeer(peer) {
    const client = new net.Socket();
    const clientRandom = generateRandomString();
    let sessionKey;
    let premasterSecret;

    client.connect(peer.port, "localhost", () => {
      console.log(`[${this.name}] Connecting to ${peer.name}`);
      const helloMessage = {
        type: "hello",
        clientRandom,
      };
      client.write(JSON.stringify(helloMessage));
    });

    client.on("data", async (data) => {
      const message = JSON.parse(data.toString());

      if (message.type === "serverHello") {
        const isValid = await this.verifyCertificate(
          message.serverCert
        );
        if (!isValid) {
          console.log(`[${this.name}] Server certificate is invalid.`);
          client.destroy();
          return;
        }

        console.log(`[${this.name}] Received serverHello from ${peer.name}`);

        premasterSecret = generateRandomString();

        const encryptedPremaster = encryptWithPublicKey(
          message.serverCert.publicKey,
          premasterSecret
        );

        const premasterMessage = {
          type: "premaster",
          clientRandom,
          encryptedPremaster: encryptedPremaster.toString("base64"),
        };

        client.write(JSON.stringify(premasterMessage));
      } else if (message.type === "ready") {
        sessionKey = deriveSessionKey(
          clientRandom,
          message.serverRandom,
          premasterSecret
        );

        console.log(
          `[${this.name}] Session key established with ${peer.name}: ${sessionKey}`
        );

        const serverMessage = decryptWithSessionKey(
          sessionKey,
          message.message
        );

        if (serverMessage === "serverReady") {
          console.log(`[${this.name}] Server is ready. Sending clientReady...`);

          const secureMessage = encryptWithSessionKey(
            sessionKey,
            "clientReady"
          );
          client.write(
            JSON.stringify({
              type: "clientReady",
              clientRandom,
              message: secureMessage,
            })
          );

          this.clientConnections.push({
            serverName: peer.name,
            serverPort: peer.port,
            sessionKey,
            socket: client,
          });
        } else {
          console.log("Invalid message from server.");
        }
      }
    });

    client.on("error", (err) => {
      console.error(`[${this.name}] Error connecting to ${peer.name}: ${err}`);
    });
  }

  sendFile(peerName, filePath) {
    const connection = this.clientConnections.find(
      (conn) => conn.serverName === peerName
    );
    if (!connection) {
      console.log(`[${this.name}] No active session with ${peerName}`);
      return;
    }

    const { socket, sessionKey } = connection;

    const fileData = fs.readFileSync(filePath, "utf8");
    const secureFileData = encryptWithSessionKey(sessionKey, fileData);

    console.log(`[${this.name}] Sending file to ${peerName}: ${filePath}`);
    socket.write(
      JSON.stringify({
        type: "file",
        fileName: filePath.split("/").pop(),
        fileData: secureFileData,
      })
    );
  }

  signCertificate(publicKey, subject, callback) {
    const client = new net.Socket();

    client.connect(4000, "localhost", () => {
      console.log(`[${this.name}] Connecting to CA Server for certificate...`);
      const request = {
        type: "signCertificate",
        publicKey,
        subject,
      };
      client.write(JSON.stringify(request));
    });

    client.on("data", (data) => {
      const response = JSON.parse(data.toString());
      if (response.error) {
        console.error(`[${this.name}] Error from CA Server: ${response.error}`);
        callback(null);
      } else {
        callback(response);
      }
      client.destroy();
    });

    client.on("error", (err) => {
      console.error(
        `[${this.name}] Error connecting to CA Server: ${err.message}`
      );
      callback(null);
      client.destroy();
    });
  }

  verifyCertificate(serverCert) {
    return new Promise((resolve, reject) => {
      const client = new net.Socket();

      client.connect(4000, "localhost", () => {
        console.log(
          `[${this.name}] Sending certificate to CA Server for verification...`
        );
        const request = {
          type: "verifyCertificate",
          certificate: serverCert,
        };
        client.write(JSON.stringify(request));
      });

      client.on("data", (data) => {
        const response = JSON.parse(data.toString());
        if (response.verified) {
          console.log(`[${this.name}] Certificate verified successfully.`);
          resolve(true);
        } else {
          console.log(`[${this.name}] Certificate verification failed.`);
          resolve(false);
        }
        client.destroy();
      });

      client.on("error", (err) => {
        console.error(
          `[${this.name}] Error connecting to CA Server: ${err.message}`
        );
        resolve(false);
        client.destroy();
      });
    });
  }
}

module.exports = Node;
