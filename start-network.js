const fs = require('fs');
const path = require('path');
const Node = require("./node");
const CAServer = require("./ca-server");

const checkAndCreateDirectories = () => {
  const receivedDir = path.join(__dirname, 'received');
  const certsDir = path.join(__dirname, 'certs');

  if (!fs.existsSync(receivedDir)) {
    fs.mkdirSync(receivedDir);
    console.log('Created directory: received');
  }

  if (!fs.existsSync(certsDir)) {
    fs.mkdirSync(certsDir);
    console.log('Created directory: certs');
  }
};

checkAndCreateDirectories();

const node1 = new Node("Node1", 3001);
const node2 = new Node("Node2", 3002);
const node3 = new Node("Node3", 3003);
const CAServer1 = new CAServer();

const startServers = () => {
  CAServer1.startServer();
  node1.startServer();
  node2.startServer();
  node3.startServer();
};

const connectPeers = () => {
  node1.connectToPeer({ name: "Node2", port: 3002 });
  node2.connectToPeer({ name: "Node3", port: 3003 });
  node3.connectToPeer({ name: "Node1", port: 3001 });
};

const sendFiles = () => {
  node1.sendFile("Node2", "./text.txt");
  node2.sendFile("Node3", "./text2.txt");
};

const main = async () => {
  startServers();
  setTimeout(async () => {
    connectPeers();
  }, 1000);

  setTimeout(async () => {
    sendFiles();
  }, 5000);
};

main();
