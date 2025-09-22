import { useRef } from "react";
import { MlKem768 } from "crystals-kyber-js";
import { falcon  } from "falcon-crypto";

export function useCrypto() {
  const stateRef = useRef({
    kyberKeys: null,       // {kem, pk, sk}
    falconKeys: {},      // {pk, sk}
    sharedSecrets: {},     // peerId -> Uint8Array
    aesKeys: {},           // peerId -> CryptoKey
  });

  const state = stateRef.current;

  // Generate Kyber + Falcon key pairs
  const generateKeys = async () => {
    console.log("Generating Kyber and Falcon key pairs...");

    // Kyber
    const kem = new MlKem768();
    const [kyberPk, kyberSk] = await kem.generateKeyPair();
    state.kyberKeys = { kem, pk: kyberPk, sk: kyberSk };

    // Falcon
    const keyPair = await falcon.keyPair();
    state.falconKeys = { pk: keyPair.publicKey, sk: keyPair.privateKey };

    return { kyberPk, falconPk: keyPair.publicKey };
  };

  const getMyPublicKey = () => {
    if (!state.kyberKeys) throw new Error("Kyber keys not generated yet");
    if (!state.falconKeys) throw new Error("Falcon keys not generated yet");
    return { kyberPk: state.kyberKeys.pk, falconPk: state.falconKeys.pk };
  };

  // Establish shared secret using peer Kyber public key
  const establishSharedSecret = async (peerId, peerKyberPkArray) => {
    const peerPk = new Uint8Array(peerKyberPkArray);
    const kem = state.kyberKeys.kem;

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

    return { ct, aesKey };
  };

  // Decapsulate ciphertext from peer
  const decapsulate = async (peerId, ctArray) => {
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
    return aesKey;
  };

  // AES encryption
  const encryptAES = async (text, peerId) => {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
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
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      state.aesKeys[peerId],
      ciphertext
    );
    return dec.decode(decrypted);
  };

  // Falcon sign (detached)
  const signMessage = async (msg) => {
    const encoded = new TextEncoder().encode(msg);
    const signature = await falcon.signDetached(encoded, state.falconKeys.sk);
    return signature;
  };

  const addFalconKey = (peerId, key) => {
      state.falconKeys[peerId] = key;
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
  };

  return {
    generateKeys,
    getMyPublicKey,
    establishSharedSecret,
    decapsulate,
    encryptAES,
    decryptAES,
    signMessage,
    verifyMessage,
    sendMessage,
    aesKeys: state.aesKeys,
    addFalconKey,
    falconKeys: state.falconKeys,
  };
}
