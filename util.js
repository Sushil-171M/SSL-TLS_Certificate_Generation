const express = require("express");
// const generateCACertificates =  require('./cert')
const forge = require("node-forge");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

function convertPKCS1ToPKCS8Format(privateKey) {
  const privateKeyPKCS8 = forge.pki.privateKeyToAsn1(privateKey);
  const privateKeyInfo = forge.pki.wrapRsaPrivateKey(privateKeyPKCS8);
  const pkcs8Pem = forge.pem.encode({
    type: "PRIVATE KEY",
    body: forge.asn1.toDer(privateKeyInfo).getBytes(),
  });
  return pkcs8Pem;
}

// Convert certificates and keys to PEM format
function convertToPEM(cert, key) {
  const certPEM = forge.pki.certificateToPem(cert);
  const privateKeyPEM = convertPKCS1ToPKCS8Format(key.privateKey);
  const publicKeyPEM = forge.pki.publicKeyToPem(key.publicKey);
  return { certPEM, privateKeyPEM, publicKeyPEM };
}

function createFolderAndFile(fileName, cert, key) {
  const folderPath = path.join(__dirname, `Certs/`);
  const filePathCert = path.join(folderPath, `${fileName}.cert.pem`);
  const filePathKey = path.join(folderPath, `${fileName}.key`);

  if (!fs.existsSync(folderPath)) {
    fs.mkdirSync(folderPath, { recursive: true });
  }

  fs.writeFile(filePathCert, cert, (err) => {
    if (err) {
      console.error("Error writing file:", err);
    } else {
      console.log("File has been saved in the folder successfully!");
    }
  });

  fs.writeFile(filePathKey, key, (err) => {
    if (err) {
      console.error("Error writing file:", err);
    } else {
      console.log("File has been saved in the folder successfully!");
    }
  });
}

module.exports = {
  convertToPEM,
  createFolderAndFile
};
