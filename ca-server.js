const net = require("net");
const fs = require("fs");
const crypto = require("crypto");

const CA_CERT_PATH = "./certs/ca-cert.pem";
const CA_KEY_PATH = "./certs/ca-key.pem";
const CA_SERVER_PORT = 4000;

class CAServer {
  constructor() {
    if (this.certExists()) {
      console.log("CA Certificate and key found.");
      this.caCert = JSON.parse(fs.readFileSync(CA_CERT_PATH, "utf8"));
      this.caPrivateKey = crypto.createPrivateKey(
        fs.readFileSync(CA_KEY_PATH, "utf8")
      );
    } else {
      console.log("CA Certificate and key not found. Generating new ones.");
      this.generateCACertificate();
    }
  }

  certExists() {
    return fs.existsSync(CA_CERT_PATH) && fs.existsSync(CA_KEY_PATH);
  }

  generateCACertificate() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });

    const caCertificate = {
      subject: "CA",
      validFrom: new Date(),
      validTo: new Date(new Date().setFullYear(new Date().getFullYear() + 1)),
      publicKey: publicKey.export({ type: "pkcs1", format: "pem" }),
      issuer: "CA",
    };

    const signature = crypto.sign(
      "sha256",
      Buffer.from(JSON.stringify(caCertificate)),
      privateKey
    );
    caCertificate.signature = signature.toString("base64");

    fs.writeFileSync(CA_CERT_PATH, JSON.stringify(caCertificate));
    fs.writeFileSync(CA_KEY_PATH, privateKey.export({ type: "pkcs1", format: "pem" }));

    this.caCert = caCertificate;
    this.caPrivateKey = privateKey;

    console.log("New CA certificate and key generated.");
  }

  startServer() {
    const server = net.createServer((socket) => {
      console.log("Client connected to CA Server.");

      socket.on("data", (data) => {
        const request = JSON.parse(data.toString());

        if (request.type === "verifyCertificate") {
          const isVerified = this.verifyCertificate(request.certificate);
          socket.write(JSON.stringify({ verified: isVerified }));
          console.log("Certificate verification result sent.");
        } else if (request.type === "signCertificate") {
          const newCert = this.signCertificate(
            request.publicKey,
            request.subject
          );
          socket.write(JSON.stringify(newCert));
          console.log("New certificate issued and sent.");
        } else {
          console.log("Invalid request type received.");
          socket.write(JSON.stringify({ error: "Invalid request type" }));
        }
      });

      socket.on("error", (err) => {
        console.error("Socket error in CA Server:", err.message);
      });

      socket.on("end", () => {
        console.log("Client disconnected from CA Server.");
      });
    });

    server.listen(CA_SERVER_PORT, () => {
      console.log(`CA Server is running on port ${CA_SERVER_PORT}`);
    });
  }

  verifyCertificate(serverCert) {
    const caPublicKey = this.caCert.publicKey;
    const serverCertData = { ...serverCert };
    delete serverCertData.signature;

    const isVerified = crypto.verify(
      "sha256",
      Buffer.from(JSON.stringify(serverCertData)),
      caPublicKey,
      Buffer.from(serverCert.signature, "base64")
    );

    return isVerified;
  }

  signCertificate(serverPublicKey, serverName) {
    const serverCertificate = {
      subject: serverName,
      validFrom: new Date(),
      validTo: new Date(new Date().setFullYear(new Date().getFullYear() + 1)),
      publicKey: serverPublicKey,
      issuer: "CA",
    };

    const signature = crypto.sign(
      "sha256",
      Buffer.from(JSON.stringify(serverCertificate)),
      this.caPrivateKey
    );
    serverCertificate.signature = signature.toString("base64");

    return serverCertificate;
  }
}

module.exports = CAServer;
