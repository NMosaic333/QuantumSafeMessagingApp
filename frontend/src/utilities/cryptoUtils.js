// cryptoUtils.js

export const SALT_LENGTH = 16;

// Convert string to Uint8Array
export const strToBuf = (str) => new TextEncoder().encode(str);

// Convert ArrayBuffer / Uint8Array to hex string
export const bufToHex = (buffer) => {
  const byteArray = new Uint8Array(buffer);
  return Array.from(byteArray)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
};

// Convert hex string to ArrayBuffer
export const hexToBuf = (hex) => {
  const bytes = new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
  return bytes.buffer;
};

// Convert ArrayBuffer to hex string
export const arrayBufferToHex = (buffer) => {
  const byteArray = new Uint8Array(buffer);
  return Array.from(byteArray)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
};

// Convert hex string to ArrayBuffer
export const hexToArrayBuffer = (hex) => {
  const buffer = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    buffer[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return buffer.buffer;
};

// Derive an AES-GCM key from passphrase + salt using PBKDF2
export async function deriveKey(passphrase, salt) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    strToBuf(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 200000,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// AES-GCM encrypt a hex string, returns {iv, ciphertext}
export async function aesEncrypt(key, plainHex) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    hexToBuf(plainHex)
  );
  return { iv, ciphertext };
}

// AES-GCM decrypt, returns hex string
export async function aesDecrypt(key, iv, ciphertext) {
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );
  return bufToHex(decrypted);
}
