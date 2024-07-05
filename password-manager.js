"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

const FIX_POINT_1 = "anthony";
const FIX_POINT_2 = "james";

const MASTER_CHECK_CONST = "masterCheck";

/********* Implementation ********/
class Keychain {
 
  constructor(kvs, randomSalt, HMACKey, AESKey, masterCheck, swapCheck) {
    this.data = { 
      kvs: kvs,
      salt: randomSalt,
      masterCheck: masterCheck,
      swapCheck: swapCheck,
    };
    this.secrets = {
      HMACKey: HMACKey,
      AESKey: AESKey,
    };
  };

  // initializes the keychain
  static async init(password) {
    let kvs = {};
    let swapCheck = [];
    let randomSalt = getRandomBytes(64); // generate a random salt
    let encodedSalt = encodeBuffer(randomSalt); // Convert the Uint8Array to a Base64 string for easy storage
    let { masterKey, HMACKey, AESKey } = await this.getKeys(password, encodedSalt); // get the keys
    let masterCheck = await subtle.sign("HMAC", masterKey, stringToBuffer(MASTER_CHECK_CONST)); // get the master check
    masterCheck = encodeBuffer(masterCheck); // Convert masterCheck to a Base64 string for serialization

    return new Keychain(kvs, encodedSalt, HMACKey, AESKey, masterCheck, swapCheck); // initialize the keychain
  }

  // gets the masterkey, HMACKey, and AESKey from the password and salt
  static async getKeys(password, salt) {
    let decodedSalt = decodeBuffer(salt); // Assuming salt is the Base64 encoded string
    let rawKey = await subtle.importKey("raw", stringToBuffer(password), "PBKDF2", false, ["deriveKey"]);
    let PbKdf2Params = {name: "PBKDF2", salt: decodedSalt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256"};
    let HmacKeyGenParams = {name: "HMAC", hash: "SHA-256"};
    let masterKey = await subtle.deriveKey(PbKdf2Params, rawKey, HmacKeyGenParams, true, ["sign", "verify"]);

    let HMACKeyMaterial = await subtle.sign("HMAC", masterKey, stringToBuffer(FIX_POINT_1));
    let HMACKey = await subtle.importKey("raw", HMACKeyMaterial, {name: "HMAC", hash: "SHA-256"}, false, ["sign", "verify"]);
  
    // Derive AESKey
    let AESKeyMaterial = await subtle.sign("HMAC", masterKey, stringToBuffer(FIX_POINT_2));
    let AESKey = await subtle.importKey("raw", AESKeyMaterial, {name: "AES-GCM"}, false, ["encrypt", "decrypt"]);

    return { masterKey, HMACKey, AESKey };
  }

  //loads the database on session start
  static async load(password, repr, trustedDataCheck) {

    let deserialized = JSON.parse(repr);

    let decodedSalt = decodeBuffer(deserialized.salt); // Assuming deserialized.salt is the Base64 encoded string
    let { masterKey, HMACKey, AESKey } = await this.getKeys(password, decodedSalt);

    let decodedMasterCheck = decodeBuffer(deserialized.masterCheck);

    let check = await subtle.verify("HMAC", masterKey, decodedMasterCheck, stringToBuffer(MASTER_CHECK_CONST));
    if (!check) {
      throw new Error("Integrity check failed");
    }
    let hashedData = await subtle.digest("SHA-256", stringToBuffer(repr));
    let hashedDataInBase64 = encodeBuffer(new Uint8Array(hashedData));

    if (trustedDataCheck && hashedDataInBase64 !== trustedDataCheck) {
      throw new Error("Integrity check failed");
    }

    Object.keys(deserialized.kvs).forEach(key => {
      let value = deserialized.kvs[key];
      if (value.type === 'Buffer') {
        deserialized.kvs[key] = new Uint8Array(value.data);
      }
    });

    let kvs = deserialized.kvs;
    let keyChain = new Keychain(kvs, decodedSalt, HMACKey, AESKey, decodedMasterCheck);
    return keyChain;
  };

  // dumps the database for session end
  async dump() {
    let returnData = [];
    returnData.push(JSON.stringify(this.data));

    let hashedData = await subtle.digest("SHA-256", stringToBuffer(JSON.stringify(this.data)));
    let hashedDataInBase64 = encodeBuffer(new Uint8Array(hashedData));
    returnData.push(hashedDataInBase64);

    return returnData;
  };

  // gets the password for the domain (name)
  async get(name) {
    let macDomainBuffer = await subtle.sign("HMAC", this.secrets.HMACKey, stringToBuffer(name));
    let macDomain = encodeBuffer(macDomainBuffer); // Use encodeBuffer to convert to a unique string
    let storedData = this.data.kvs[macDomain];
    if (storedData) {
      let iv = decodeBuffer(storedData.slice(0, 24)); // Assuming the IV is the first 16 bytes
      let actualEncryptedData = decodeBuffer(storedData.slice(24));
      let paddedValue = await subtle.decrypt({ name: "AES-GCM", iv: iv, additionalData: macDomainBuffer }, this.secrets.AESKey, actualEncryptedData);
      let paddedPass = bufferToString(paddedValue);

      // logic to remove padding
      let code = parseInt(paddedPass[64] + paddedPass[65] + paddedPass[66], 10);
      return paddedPass.substring(0, code);

      
    }
    return null;
  };

  // sets the domain (name) and its password (value)
  async set(name, value) {
    // logic to add padding
    let length = value.length;
    for (let i = length; i < (MAX_PASSWORD_LENGTH); i++) {
      value += '0';
    }
    if (length <= 9) {
      value += '00' + length.toString();
    } else if (length <= 99) {
      value += '0' + length.toString();
    } else {
      value += length.toString();
    }

    let macDomainBuffer = await subtle.sign("HMAC", this.secrets.HMACKey, stringToBuffer(name));
    let macDomain = encodeBuffer(macDomainBuffer); // Use encodeBuffer to convert to a unique string

    let iv = getRandomBytes(16);
    let encValue = await subtle.encrypt({ name: "AES-GCM", iv: iv, additionalData: macDomainBuffer }, this.secrets.AESKey, stringToBuffer(value));
    let buffer = encodeBuffer(iv) + encodeBuffer(encValue)
    
    console.log(buffer.length)
    console.log(encodeBuffer(iv).length)
    this.data.kvs[macDomain] = buffer; 
    return;
  };

  // removes the domain (name) and its password 
  async remove(name) {
    let macDomainBuffer = await subtle.sign("HMAC", this.secrets.HMACKey, stringToBuffer(name));
    let macDomain = encodeBuffer(macDomainBuffer); // Use encodeBuffer to convert to a unique string
    let storedData = this.data.kvs[macDomain];

    if (storedData) {
      delete this.data.kvs[macDomain];
      return true;
    }
    return false;
  };
};

module.exports = { Keychain }