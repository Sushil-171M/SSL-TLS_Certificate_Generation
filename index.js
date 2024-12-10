const express = require("express");
const fs = require("fs");
const path = require("path");
const forge = require("node-forge");
const crypto = require("crypto");

const {
  convertToPEM,
  createFolderAndFile,
} = require("./util");

const app = express();
const port = 3001;

app.get("/", (req, res) => {
  res.send("Home Page");
});

app.get("/generate", (req, res) => {
  const { caCert, caKeys } = generateCACertificate();

  const hostName = '1.2.3.4'

  // Generate CSR for server
  const serverCSR = generateCSR(hostName, true);
  // Sign the server CSR
  const serverCert = signCSR(serverCSR.csr, caCert, caKeys, true);

  // Generate CSR for client
  const clientCSR = generateCSR(hostName, false);
  // Sign the client CSR
  const clientCert = signCSR(clientCSR.csr, caCert, caKeys, false);

  const caPEM = convertToPEM(caCert, caKeys);
  const serverPEM = convertToPEM(serverCert, serverCSR.keys);
  const clientPEM = convertToPEM(clientCert, clientCSR.keys);

  createFolderAndFile("server", serverPEM.certPEM, serverPEM.privateKeyPEM);
  createFolderAndFile("ca", caPEM.certPEM, caPEM.privateKeyPEM);
  createFolderAndFile("client", clientPEM.certPEM, clientPEM.privateKeyPEM);

  res.status(200).send(({caPEM:caPEM.certPEM, serverPEM, clientPEM}))});

// Step 1: Generate CA Certificate
function generateCACertificate() {
  const caKeys = forge.pki.rsa.generateKeyPair(2048);
  const caCert = forge.pki.createCertificate();

  caCert.publicKey = caKeys.publicKey;

  const serialNumber = crypto.randomBytes(16);
  serialNumber[0] &= 0x7f; 
  caCert.serialNumber = serialNumber.toString("hex");

  caCert.validity.notBefore = new Date();
  caCert.validity.notAfter = new Date();
  caCert.validity.notAfter.setFullYear(
    caCert.validity.notBefore.getFullYear() + 1
  );

  caCert.setSubject([
    { name: "countryName", value: "India" },
    { name: "stateOrProvinceName", value: "Surat" },
    { name: "localityName", value: "Nandanvan" },
    { name: "organizationName", value: "Alpha" },
    {
      name: "organizationalUnitName",
      value: "Digi Cert",
    },
    { name: "commonName", value: "Digi Cert" },
  ]);

  caCert.setIssuer(caCert.subject.attributes);

  caCert.setExtensions([
    { name: "subjectKeyIdentifier", keyIdentifier: true },
    {
      name: "authorityKeyIdentifier",
      keyIdentifier: true,
      authorityCertIssuer: true,
      serialNumber: true,
    },
    { name: "basicConstraints", cA: true },
  ]);

  caCert.sign(caKeys.privateKey, forge.md.sha256.create());

  return { caCert, caKeys};
}

// Step 2: Generate CSR
function generateCSR(commonName, isServer = true) {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = keys.publicKey;
  const OU = isServer ? "Alpha" : "platform";   // depned on cert e.g server or client

  csr.setSubject([
    { name: "countryName", value: "India" },
    { name: "stateOrProvinceName", value: "Surat" },
    { name: "localityName", value: "Nandanvan" },
    { name: "organizationName", value: "Alpha" },
    { name: "organizationalUnitName", value: OU },
    { name: "commonName", value: commonName },
  ]);

  csr.sign(keys.privateKey, forge.md.sha256.create());

  return { csr, keys };
}

// Step 3: Sign the CSR using the CA
function signCSR(csr, caCert, caKeys, isServer = true) {
  const cert = forge.pki.createCertificate();
  const serialNumber = crypto.randomBytes(16);
  serialNumber[0] &= 0x7f; // Ensure the first byte is non-negative
  cert.serialNumber = serialNumber.toString("hex");
  cert.publicKey = csr.publicKey;

  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(
    cert.validity.notBefore.getFullYear() + 40
  );
  const extUsage = isServer
    ? {
        name: "extKeyUsage",
        serverAuth: true, // Indicates TLS Web Server Authentication
      }
    : {
        name: "extKeyUsage",
        clientAuth: true, // Indicates TLS Web Server Authentication
      };
  // Copy the CSR subject
  cert.setSubject(csr.subject.attributes);

  // Set the issuer to the CA
  cert.setIssuer(caCert.subject.attributes);

  // Add extensions
  cert.setExtensions([
    {
      name: "subjectKeyIdentifier",
      keyIdentifier: true,
    },
    {
      name: "authorityKeyIdentifier",
      keyIdentifier: caCert.getExtension("subjectKeyIdentifier").value.value,
      authorityCertIssuer: true,
      serialNumber: caCert.serialNumber,
    },
    {
      name: "keyUsage",
      digitalSignature: true,
      keyEncipherment: true,
    },
    { name: "basicConstraints", cA: false },
    extUsage,
    {
      name: "subjectAltName",
      altNames: [
        { type: 2, value: csr.subject.getField("CN").value },
      ],
    },
  ]);

  cert.sign(caKeys.privateKey, forge.md.sha256.create());
  return cert;
}

app.listen(port, () => {
  console.log(`Server is running on Port ${port}`, port);
});
