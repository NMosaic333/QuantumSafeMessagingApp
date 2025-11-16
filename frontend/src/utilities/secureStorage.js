import { db } from "./db";
import { deriveKey, aesEncrypt, aesDecrypt, hexToArrayBuffer, arrayBufferToHex, bufToHex, hexToBuf } from "./cryptoUtils";

export async function storeIdentityKeys(userId, passphrase, kyberKeys, falconKeys) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const aesKey = await deriveKey(passphrase, salt);

  const { iv: ivKyber, ciphertext: encKyber } = await aesEncrypt(aesKey, bufToHex(kyberKeys.sk));
  const { iv: ivFalcon, ciphertext: encFalcon } = await aesEncrypt(aesKey, bufToHex(falconKeys.sk));

  
  await db.identity.put({
    userId,
    kyberPk: bufToHex(kyberKeys.pk),
    falconPk: bufToHex(falconKeys.pk),
    encKyberSk: arrayBufferToHex(encKyber),
    kyberIv: arrayBufferToHex(ivKyber),
    encFalconSk: arrayBufferToHex(encFalcon),
    falconIv: arrayBufferToHex(ivFalcon),
    salt: arrayBufferToHex(salt),
  });
}

export async function loadIdentityKeys(userId, passphrase) {
  const row = await db.identity.get(userId);
  if (!row || row.userId !== userId) return null;

  const aesKey = await deriveKey(passphrase, hexToArrayBuffer(row.salt));

  const kyberSk = await aesDecrypt(
    aesKey,
    hexToArrayBuffer(row.kyberIv),
    hexToArrayBuffer(row.encKyberSk)
  );

  const falconSk = await aesDecrypt(
    aesKey,
    hexToArrayBuffer(row.falconIv),
    hexToArrayBuffer(row.encFalconSk)
  );

  return {
    kyber: { pk: row.kyberPk, sk: kyberSk },
    falcon: { pk: row.falconPk, sk: falconSk },
  };
}

export async function addPeer(userId, peerId, peerKyberPk, sharedAESKey, passphrase, falconPk) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const aesKey = await deriveKey(passphrase, salt);
  const { iv, ciphertext } = await aesEncrypt(aesKey, bufToHex(sharedAESKey));

  const record = {
    userId,
    peerId,
    kyberPk: peerKyberPk,
    encSharedKey: arrayBufferToHex(ciphertext),
    iv: arrayBufferToHex(iv),
    salt: arrayBufferToHex(salt),
  };

  if (falconPk) {
    // store falconPk in hex form if provided
    if (typeof falconPk === "string") {
      record.falconPk = falconPk.startsWith("0x") ? falconPk.slice(2) : falconPk;
    } else if (falconPk instanceof Uint8Array || Array.isArray(falconPk)) {
      record.falconPk = bufToHex(new Uint8Array(falconPk));
    } else if (falconPk instanceof ArrayBuffer) {
      record.falconPk = bufToHex(new Uint8Array(falconPk));
    }
  }

  await db.peers.add(record);
}

export async function deriveStoredSharedKey(userId, peerId, passphrase) {
  const row = await db.peers
    .where("[userId+peerId]")
    .equals([userId, peerId])
    .first();

  if (!row) return null;

  const aesKey = await deriveKey(passphrase, hexToArrayBuffer(row.salt));
  const hex = await aesDecrypt(aesKey, hexToArrayBuffer(row.iv), hexToArrayBuffer(row.encSharedKey));
  return hexToBuf(hex); // returns Uint8Array for AES import
}

export async function storeMessage(userId, peerId, direction, text, aesCryptoKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesCryptoKey,
    enc.encode(text)
  );

  await db.messages.add({
    userId,
    peerId,
    direction,
    ciphertext,
    iv,
    createdAt: Date.now(),
  });
}

export async function loadMessages(userId, peerId, aesCryptoKey) {
  const msgs = await db.messages.where({ userId, peerId }).sortBy("createdAt");
  const dec = new TextDecoder();

  return Promise.all(
    msgs.map(async (m) => {
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: m.iv },
        aesCryptoKey,
        m.ciphertext
      );
      return {
        from: m.direction === "incoming" ? peerId : userId,
        text: dec.decode(decrypted),
        timestamp: new Date(m.createdAt),
      };
    })
  );
}

// Check whether identity exists for a given user
export async function hasIdentity(userId) {
  const row = await db.identity.get(userId);
  return !!row;
}

// Return stored public keys for a user (Uint8Array), or null
export async function getStoredPublicKeys(userId) {
  const row = await db.identity.get(userId);
  if (!row) return null;
  return {
    kyberPk: new Uint8Array(hexToArrayBuffer(row.kyberPk)),
    falconPk: new Uint8Array(hexToArrayBuffer(row.falconPk)),
  };
}

// Persist a peer's Falcon public key into the peers table
export async function storeFalconPeerKey(peerId, falconPk) {
  if (!peerId || !falconPk) throw new Error("peerId and falconPk required");

  let hex;
  // Validate key format before storing
  function isHexString(s) {
    return /^[0-9a-fA-F]+$/.test(s);
  }

  function validateFalconPublicKey(input) {
    if (!input) return false;
    if (typeof input === "string") {
      const candidate = input.startsWith("0x") ? input.slice(2) : input;
      // must be even-length hex and reasonable length
      if (candidate.length % 2 !== 0) return false;
      if (!isHexString(candidate)) return false;
      const bytesLen = candidate.length / 2;
      return bytesLen >= 16 && bytesLen <= 8192; // arbitrary bounds
    }
    if (input instanceof Uint8Array || Array.isArray(input)) {
      const len = input.length;
      return len >= 16 && len <= 8192;
    }
    if (input instanceof ArrayBuffer) {
      const len = input.byteLength;
      return len >= 16 && len <= 8192;
    }
    return false;
  }

  if (!validateFalconPublicKey(falconPk)) throw new Error("Invalid Falcon public key format/length");

  if (typeof falconPk === "string") {
    hex = falconPk.startsWith("0x") ? falconPk.slice(2) : falconPk;
  } else if (falconPk instanceof Uint8Array || Array.isArray(falconPk)) {
    hex = bufToHex(new Uint8Array(falconPk));
  } else if (falconPk instanceof ArrayBuffer) {
    hex = bufToHex(new Uint8Array(falconPk));
  } else {
    throw new Error("Unsupported falconPk format");
  }

  const existing = await db.peers.where("peerId").equals(peerId).first();
  if (existing) {
    await db.peers.update(existing.id, { falconPk: hex });
  } else {
    await db.peers.add({ peerId, falconPk: hex });
  }
}

// Retrieve a peer's Falcon public key (returns Uint8Array or null)
export async function getFalconPeerKey(peerId) {
  const row = await db.peers.where("peerId").equals(peerId).first();
  if (!row || !row.falconPk) return null;
  return new Uint8Array(hexToArrayBuffer(row.falconPk));
}
