const crypto = require("crypto");

function generateKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  return { publicKey, privateKey };
}

function encryptWithPublicKey(publicKey, data) {
  return crypto.publicEncrypt(publicKey, Buffer.from(data));
}

function decryptWithPrivateKey(privateKey, encryptedData) {
  return crypto.privateDecrypt(privateKey, encryptedData).toString();
}

function generateRandomString() {
  return crypto.randomBytes(16).toString("hex");
}

function deriveSessionKey(clientRandom, serverRandom, premasterSecret) {
  const hash = crypto.createHash("sha256");
  hash.update(clientRandom + serverRandom + premasterSecret);
  return hash.digest("hex");
}

function encryptWithSessionKey(sessionKey, data) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(
    "aes-256-cbc",
    Buffer.from(sessionKey, "hex"),
    iv
  );
  let encrypted = cipher.update(data, "utf8", "base64");
  encrypted += cipher.final("base64");
  return `${iv.toString("base64")}:${encrypted}`;
}

function decryptWithSessionKey(sessionKey, encryptedData) {
  if (typeof encryptedData !== "string") {
    encryptedData = encryptedData.toString();
  }
  const [ivBase64, encryptedBase64] = encryptedData.split(":");
  const iv = Buffer.from(ivBase64, "base64");
  const encrypted = Buffer.from(encryptedBase64, "base64");

  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    Buffer.from(sessionKey, "hex"),
    iv
  );
  let decrypted = decipher.update(encrypted, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}


module.exports = {
  generateKeys,
  encryptWithPublicKey,
  decryptWithPrivateKey,
  generateRandomString,
  deriveSessionKey,
  encryptWithSessionKey,
  decryptWithSessionKey,
};
