import Dexie from "dexie";

export const db = new Dexie("CryptoChatDB");

db.version(1).stores({
  // Each device of a user has its own identity
  identity: "&userId, kyberPk, falconPk, encKyberSk, kyberIv, encFalconSk, falconIv, salt",

  // Messages between user and peer
  messages: "++id, [userId+peerId], direction, ciphertext, iv, createdAt",
});

db.version(2).stores({
  // Keep previous stores and add peers. When bumping DB version include all stores for that version.
  identity: "&userId, kyberPk, falconPk, encKyberSk, kyberIv, encFalconSk, falconIv, salt",
  messages: "++id, [userId+peerId], direction, ciphertext, iv, createdAt",
  // Peers for a user: stores shared keys with each peer device. Include userId index for simple queries.
  peers: "++id, userId, peerId, [userId+peerId], kyberPk, falconPk, encSharedKey, iv, salt",
})