import { useEffect, useRef } from "react";
import { MlKem768 } from "crystals-kyber-js";
import { falcon  } from "falcon-crypto";
import { storeIdentityKeys, loadIdentityKeys, addPeer, deriveStoredSharedKey, storeMessage, loadMessages, storeFalconPeerKey, getFalconPeerKey, hasIdentity, getStoredPublicKeys } from "./secureStorage";
import { db } from "./db";

export function useCrypto() {
  const stateRef = useRef({
    userId: null,
    kyberKeys: { kem: null, pk: null, sk: null },       // {kem, pk, sk}
    falconKeys: {},      // {pk, sk}
    sharedSecrets: {},     // peerId -> Uint8Array
    aesKeys: {},           // peerId -> CryptoKey
    // falcon public keys are persisted in IndexedDB; avoid in-memory cache to reduce statefulness
  });

  const state = stateRef.current;

  const loadPeerMessages = async (userId) => {
    const rows = await db.peers.where("userId").equals(userId).toArray();
    const result = {};

    function toUint8Array(input) {
      if (!input) throw new Error("Peer Falcon key missing!");

      if (input instanceof Uint8Array) return input;

      if (Array.isArray(input)) return new Uint8Array(input);

      if (typeof input === "string") {
        const hex = input.startsWith("0x") ? input.slice(2) : input;
        if (hex.length % 2 !== 0) throw new Error("Invalid hex length");
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
          bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
        }
        return bytes;
      }

      throw new Error("Unsupported key format for peer Falcon key");
    }

    for (const row of rows) {
      try {
        // Convert stored shared secret from hex → ArrayBuffer
        const ss = await deriveStoredSharedKey(row.userId, row.peerId, "user-passphrase");
        // Convert to AES key
        const aesKey = await crypto.subtle.importKey(
          "raw",
          ss,
          { name: "AES-GCM" },
          false,
          ["encrypt", "decrypt"]
        );

        // Load & decrypt all messages with this peer
        const msgs = await loadMessages(userId, row.peerId, aesKey);

        result[row.peerId] = msgs;
      } catch (err) {
        console.warn(`Could not restore chat with ${row.peerId}`, err);
        result[row.peerId] = []; // prevent crash
      }
    }

    return result;
  }

  function hexToUint8(hex) {
    if (hex.length % 2 !== 0) throw new Error("Invalid hex string length");
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }

  const loadKeys = async (userId) => {
    // Load keys from secure storage (not implemented here)
    // You would typically call loadIdentityKeys from secureStorage.js
    // and populate state.kyberKeys and state.falconKeys accordingly.
    const kem = new MlKem768();
    const { kyber, falcon } = await loadIdentityKeys(userId, "user-passphrase");
    state.kyberKeys.kem = kem;
    state.kyberKeys.sk = hexToUint8(kyber.sk);
    state.kyberKeys.pk = hexToUint8(kyber.pk);
    state.falconKeys.sk = hexToUint8(falcon.sk);
    state.falconKeys.pk = hexToUint8(falcon.pk);
    state.userId = userId;
  }

  // Generate Kyber + Falcon key pairs
  const generateKeys = async (userId) => {
    console.log("Generating Kyber and Falcon key pairs...");

    // Kyber
    const kem = new MlKem768();
    const [kyberPk, kyberSk] = await kem.generateKeyPair();
    state.kyberKeys = { kem, pk: kyberPk, sk: kyberSk };
    state.userId = userId;

    // Falcon
    const keyPair = await falcon.keyPair();
    state.falconKeys = { pk: keyPair.publicKey, sk: keyPair.privateKey };

    await storeIdentityKeys(userId, "user-passphrase", state.kyberKeys, state.falconKeys);

    console.log("✅ Kyber and Falcon key pairs generated and stored securely.");
    return { kyberPk, falconPk: keyPair.publicKey };
  };

  const getMyPublicKey = () => {
    if (!state.kyberKeys) throw new Error("Kyber keys not generated yet");
    if (!state.falconKeys) throw new Error("Falcon keys not generated yet");
    return { kyberPk: state.kyberKeys.pk, falconPk: state.falconKeys.pk };
  };

  // Establish shared secret using peer Kyber public key
  const establishSharedSecret = async (peerId, peerKyberPkArray) => {
    const kem = state.kyberKeys.kem;
    const peerPk = new Uint8Array(peerKyberPkArray);
    const [ct, ss] = await kem.encap(peerPk);
    state.sharedSecrets[peerId] = ss;

    const aesKey = await crypto.subtle.importKey(
      "raw",
      ss,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
    state.aesKeys[peerId] = aesKey;
    try {
      const storedFalcon = await getFalconPeerKey(peerId);
      await addPeer(state.userId, peerId, peerPk, ss, "user-passphrase", storedFalcon);
    } catch (e) {
      await addPeer(state.userId, peerId, peerPk, ss, "user-passphrase");
    }
    return { ct };
  };

  // Decapsulate ciphertext from peer
  const decapsulate = async (peerId, ctArray, peerKyberPkArray) => {
    const peerPk = new Uint8Array(peerKyberPkArray);
    const ct = new Uint8Array(ctArray);
    const ss = await state.kyberKeys.kem.decap(ct, state.kyberKeys.sk);
    state.sharedSecrets[peerId] = ss;

    const aesKey = await crypto.subtle.importKey(
      "raw",
      ss,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
    state.aesKeys[peerId] = aesKey;
    try {
      const storedFalcon = await getFalconPeerKey(peerId);
      await addPeer(state.userId, peerId, peerPk, ss, "user-passphrase", storedFalcon);
    } catch (e) {
      await addPeer(state.userId, peerId, peerPk, ss, "user-passphrase");
    }
  };

  // AES encryption
  const encryptAES = async (text, peerId) => {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    if (!state.aesKeys[peerId]) {
      const ss = await deriveStoredSharedKey(state.userId, peerId, "user-passphrase");
      if (!ss) {
        throw new Error("Shared secret missing — cannot restore AES key");
      }
      const aesKey = await crypto.subtle.importKey(
        "raw",
        ss,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
      );
      state.aesKeys[peerId] = aesKey;
    }
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      state.aesKeys[peerId],
      enc.encode(text)
    );
    return { ciphertext: Array.from(new Uint8Array(ciphertext)), iv: Array.from(iv) };
  };

  // AES decryption
  const decryptAES = async (ciphertextArray, ivArray, peerId) => {
    const dec = new TextDecoder();
    const ciphertext = new Uint8Array(ciphertextArray);
    const iv = new Uint8Array(ivArray);
    if (!state.aesKeys[peerId]) {
      const ss = await deriveStoredSharedKey(state.userId, peerId, "user-passphrase");
      const aesKey = await crypto.subtle.importKey(
        "raw",
        ss,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
      );
      state.aesKeys[peerId] = aesKey;
    }
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      state.aesKeys[peerId],
      ciphertext
    );
    await storeMessage(state.userId, peerId, "incoming", dec.decode(decrypted), state.aesKeys[peerId]);
    return dec.decode(decrypted);
  };

  // Falcon sign (detached)
  const signMessage = async (msg) => {
    const encoded = new TextEncoder().encode(msg);
    const signature = await falcon.signDetached(encoded, state.falconKeys.sk);
    return signature;
  };

  const addFalconKey = async (peerId, key) => {
    // Persist peer Falcon public key to IndexedDB. Do not keep a long-lived in-memory cache.
    try {
      await storeFalconPeerKey(peerId, key);
    } catch (err) {
      console.warn("Failed to persist Falcon peer key:", err);
    }
  };

  const getFalconPublicKey = async (peerId) => {
    try {
      const pk = await getFalconPeerKey(peerId);
      return pk;
    } catch (err) {
      console.warn("Failed to read Falcon peer key from DB:", err);
      return null;
    }
  };

  // Falcon verify (detached)
  const verifyMessage = async (msg, sig, pk) => {
    const encoded = new TextEncoder().encode(msg);
    const isValid = await falcon.verifyDetached(sig, encoded, pk);
    return isValid;
  };

  // Send encrypted + signed message over websocket
  const sendMessage = async (socket, peerId, text, fromUserId) => {
    const payload = await encryptAES(text, peerId);
    const signature = await signMessage(JSON.stringify(payload));
    socket.send(JSON.stringify({
      type: "chat",
      to: peerId,
      payload,
      signature: Array.from(signature),
      from: fromUserId
    }));
    await storeMessage(fromUserId, peerId, "outgoing", text, state.aesKeys[peerId]);
  };

  return {
    loadKeys,
    generateKeys,
    getMyPublicKey,
    establishSharedSecret,
    decapsulate,
    encryptAES,
    decryptAES,
    signMessage,
    verifyMessage,
    sendMessage,
    addFalconKey,
    getFalconPublicKey,
    loadPeerMessages
  };
}
