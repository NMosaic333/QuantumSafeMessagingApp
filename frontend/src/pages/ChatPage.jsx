import React, { useState, useEffect } from "react";
import { MessageCircle, UserPlus, Users, Send, Check, X } from "lucide-react";
import { useCrypto } from "../utilities/cryptomanager";

export default function ChatPage({ socket, userId }) {
  const crypto = useCrypto();
  const [peerInput, setPeerInput] = useState("");
  const [incomingRequests, setIncomingRequests] = useState([]);
  const [activePeer, setActivePeer] = useState(null);
  const [messages, setMessages] = useState({});
  const [input, setInput] = useState("");
  const previousChats = Object.keys(messages).filter(userId => messages[userId].length > 0);

  /** 🔑 Generate keys & publish to backend */
  useEffect(() => {
    async function initKeys() {
      try {
        await crypto.generateKeys();
        const { kyberPk, falconPk } = crypto.getMyPublicKey();
        console.log("✅ Generated Kyber and Falcon key pair");

        await fetch("http://localhost:8000/api/publish_kem", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ user: userId, kem_pub: Array.from(kyberPk), falcon_pub: Array.from(falconPk) }),
        });

        console.log("✅ Public keys published to backend");
      } catch (err) {
        console.error("Error generating/publishing keys:", err);
      }
    }
    initKeys();
  }, [userId]);

  /** 📩 Handle incoming WebSocket messages */
  useEffect(() => {
    if (!socket) return;

    const handler = async (event) => {
      const data = JSON.parse(event.data);

      if (data.type === "chat_request") {
        setIncomingRequests((prev) => [...prev, data.from]);
      }

      if (data.type === "shared_secret") {
        try {
          const ctUint8 = new Uint8Array(data.ct);
          await crypto.decapsulate(data.from, ctUint8);
          setActivePeer(data.from);
          console.log("✅ Shared secret established with", data.from);
        } catch (err) {
          console.error("Failed to decapsulate shared secret:", err);
        }
      }

      if (data.type === "chat") {
        try {
          if (!crypto.aesKeys[data.from]) {
            console.warn("AES key not yet available for", data.from);
            return;
          }

          const decrypted = await crypto.decryptAES(
            data.payload.ciphertext,
            data.payload.iv,
            data.from
          );

          const sig = new Uint8Array(data.signature);
          const payload = JSON.stringify(data.payload);
          const isValid = await crypto.verifyMessage(
            payload,                  // plaintext
            sig,                        // sig (Uint8Array, not JSON string!)
            crypto.falconKeys[data.from] // pk stored from handshake
          );

           if (!isValid) {
            console.error("Signature check failed for message from", data.from);
            return; // don’t trust the message
          }

          function toBase64(uint8) {
            return btoa(String.fromCharCode(...uint8));
          }

          const timestamp = new Date().toLocaleTimeString();
          setMessages((prev) => ({
            ...prev,
            [data.from]: [
              ...(prev[data.from] || []),
              { from: data.from, text: decrypted ,ciphertext: toBase64(data.payload.ciphertext),timestamp},
            ],
          }));
        } catch (err) {
          console.error("Failed to decrypt message:", err);
        }
      }
    };

    socket.addEventListener("message", handler);
    return () => socket.removeEventListener("message", handler);
  }, [socket, crypto]);

  /** 📤 Send chat request */
  const sendChatRequest = async () => {
    const res1 = await fetch(
        `http://localhost:8000/api/get_falcon_pub/${peerInput}`
      );
      const data1 = await res1.json();
      if (!data1.fk) return alert("Peer Falcon public key not found");

      const peerFk = new Uint8Array(data1.fk);
      crypto.addFalconKey(peerInput, peerFk);
      console.log("✅ Stored Falcon public key for", peerInput);
    if (!peerInput) return;

    if (!socket || socket.readyState !== WebSocket.OPEN) {
      alert("WebSocket not connected yet!");
      return;
    }

    socket.send(JSON.stringify({ type: "chat_request", from: userId, to: peerInput }));
  };

  /** ✅ Accept chat request */
  const acceptChatRequest = async (peerId) => {
    try {
      const res = await fetch(
        `http://localhost:8000/api/get_kyber_pub/${peerId}`
      );
      const data = await res.json();
      if (!data.pk) return alert("Peer public key not found");

      const peerPk = new Uint8Array(data.pk);
      const { ct } = await crypto.establishSharedSecret(peerId, peerPk);

      const res1 = await fetch(
        `http://localhost:8000/api/get_falcon_pub/${peerId}`
      );
      const data1 = await res1.json();
      if (!data1.fk) return alert("Peer Falcon public key not found");

      const peerFk = new Uint8Array(data1.fk);
      crypto.addFalconKey(peerId, peerFk);
      console.log("✅ Stored Falcon public key for", peerId);

      socket.send(
        JSON.stringify({
          type: "shared_secret",
          from: userId,
          to: peerId,
          ct: Array.from(ct),
        })
      );

      setActivePeer(peerId);
      setIncomingRequests((prev) => prev.filter((p) => p !== peerId));
    } catch (err) {
      console.error("Failed to accept chat request:", err);
    }
  };


  /** 💬 Send chat message */
  const handleSend = async () => {
    if (!activePeer || !input.trim()) return;

    await crypto.sendMessage(socket, activePeer, input, userId);

    const timestamp = new Date().toLocaleTimeString();
    setMessages((prev) => ({
      ...prev,
      [activePeer]: [
        ...(prev[activePeer] || []),
        { from: userId, text: input, ciphertext:"", timestamp },
      ],
    }));
    setInput("");
  };

  const formatTime = (timestamp) => {
    const now = new Date();
    const messageTime = new Date(timestamp);
    const diffInHours = (now - messageTime) / (1000 * 60 * 60);
    
    if (diffInHours < 1) {
      return `${Math.floor((now - messageTime) / (1000 * 60))}m ago`;
    } else if (diffInHours < 24) {
      return `${Math.floor(diffInHours)}h ago`;
    } else {
      return `${Math.floor(diffInHours / 24)}d ago`;
    }
  };

  const getLastMessage = (userId) => {
    const userMessages = messages[userId] || [];
    return userMessages[userMessages.length - 1];
  };

  // --- UI Layer (from your first ChatPage) ---
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100">
      {/* Header */}
      <div className="bg-white shadow-sm border-b border-slate-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center space-x-3">
              <div className="bg-blue-600 rounded-lg p-2">
                <MessageCircle className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-semibold text-slate-900">
                  SecureChat
                </h1>
                <p className="text-sm text-slate-500">Welcome, {userId}</p>
              </div>
            </div>
            <div className="flex items-center space-x-2">
              <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
              <span className="text-sm text-slate-600">Connected</span>
            </div>
          </div>
        </div>
      </div>

      {/* Main Grid */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Sidebar */}
          <div className="lg:col-span-1 space-y-6">            
            {/* Previous Chats */}
            {previousChats.length > 0 && (
              <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
                <h3 className="text-lg font-medium text-slate-900 mb-4 flex items-center">
                  Recent Chats
                </h3>
                <div className="space-y-2">
                  {previousChats.map(chatUserId => {
                    const lastMessage = getLastMessage(chatUserId);
                    const isActive = activePeer === chatUserId;
                    
                    return (
                      <button
                        key={chatUserId}
                        onClick={() => setActivePeer(chatUserId)}
                        className={`w-full text-left p-3 rounded-lg transition-all duration-200 group ${
                          isActive 
                            ? 'bg-blue-50 border-2 border-blue-200' 
                            : 'hover:bg-slate-50 border-2 border-transparent'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-3 flex-1 min-w-0">
                            <div className={`w-8 h-8 rounded-full flex items-center justify-center ${
                              isActive 
                                ? 'bg-blue-600 text-white' 
                                : 'bg-gradient-to-r from-purple-500 to-pink-600 text-white'
                            }`}>
                              <span className="text-sm font-medium">
                                {chatUserId.charAt(0).toUpperCase()}
                              </span>
                            </div>
                            <div className="flex-1 min-w-0">
                              <p className={`font-medium truncate ${
                                isActive ? 'text-blue-900' : 'text-slate-900'
                              }`}>
                                {chatUserId}
                              </p>
                              {lastMessage && (
                                <p className={`text-sm truncate ${
                                  isActive ? 'text-blue-600' : 'text-slate-500'
                                }`}>
                                  {lastMessage.from === userId ? 'You: ' : ''}{lastMessage.text}
                                </p>
                              )}
                            </div>
                          </div>
                          <div className="flex items-center space-x-2">
                            {lastMessage && (
                              <span className={`text-xs ${
                                isActive ? 'text-blue-500' : 'text-slate-400'
                              }`}>
                                {formatTime(lastMessage.timestamp)}
                              </span>
                            )}
                          </div>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>
            )}
            {/* Start New Chat */}
            <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
              <h3 className="text-lg font-medium text-slate-900 mb-4 flex items-center">
                <UserPlus className="w-5 h-5 mr-2 text-blue-600" />
                Start New Chat
              </h3>
              <div className="space-y-3">
                <input
                  value={peerInput}
                  onChange={(e) => setPeerInput(e.target.value)}
                  placeholder="Enter user ID..."
                  className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all"
                />
                <button
                  onClick={sendChatRequest}
                  className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-lg transition-colors flex items-center justify-center space-x-2"
                >
                  <Send className="w-4 h-4" />
                  <span>Send Request</span>
                </button>
              </div>
            </div>

            {/* Incoming Requests */}
            {incomingRequests.length > 0 && (
              <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
                <h3 className="text-lg font-medium text-slate-900 mb-4 flex items-center">
                  <Users className="w-5 h-5 mr-2 text-amber-600" />
                  Requests ({incomingRequests.length})
                </h3>
                <div className="space-y-3">
                  {incomingRequests.map((peerId) => (
                    <div
                      key={peerId}
                      className="bg-slate-50 rounded-lg p-4 border border-slate-200"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <div className="w-8 h-8 bg-gradient-to-r from-blue-500 to-purple-600 rounded-full flex items-center justify-center">
                            <span className="text-white text-sm font-medium">
                              {peerId.charAt(0).toUpperCase()}
                            </span>
                          </div>
                          <div>
                            <p className="font-medium text-slate-900">
                              {peerId}
                            </p>
                            <p className="text-sm text-slate-500">
                              wants to chat
                            </p>
                          </div>
                        </div>
                        <div className="flex space-x-2">
                          <button
                            onClick={() => acceptChatRequest(peerId)}
                            className="p-2 bg-green-100 hover:bg-green-200 text-green-700 rounded-lg transition-colors"
                          >
                            <Check className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() =>
                              setIncomingRequests((prev) =>
                                prev.filter((p) => p !== peerId)
                              )
                            }
                            className="p-2 bg-red-100 hover:bg-red-200 text-red-700 rounded-lg transition-colors"
                          >
                            <X className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Chat Area */}
          <div className="lg:col-span-2">
            {activePeer ? (
              <div className="bg-white rounded-xl shadow-sm border border-slate-200 h-[600px] flex flex-col">
                {/* Chat Header */}
                <div className="flex items-center space-x-3 p-4 border-b border-slate-200">
                  <div className="w-10 h-10 bg-gradient-to-r from-blue-500 to-purple-600 rounded-full flex items-center justify-center">
                    <span className="text-white font-medium">
                      {activePeer.charAt(0).toUpperCase()}
                    </span>
                  </div>
                  <div>
                    <h3 className="font-medium text-slate-900">{activePeer}</h3>
                    <div className="text-sm text-green-600 flex items-center">
                      <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
                      Online • End-to-end encrypted
                    </div>
                  </div>
                </div>

                {/* Messages */}
                <div className="flex-1 overflow-y-auto p-4 space-y-4">
                {(messages[activePeer] || []).map((message, i) => (
                  <div
                    key={i}
                    className={`flex flex-col ${
                      message.from === userId ? "items-end" : "items-start"
                    }`}
                  >
                    {/* Encrypted message */}
                    <div className="text-xs text-slate-400 mb-1">
                      {message.ciphertext}
                    </div>

                    {/* Decrypted message */}
                    <div
                      className={`max-w-xs lg:max-w-md px-4 py-2 rounded-2xl ${
                        message.from === userId
                          ? "bg-blue-600 text-white rounded-br-md"
                          : "bg-slate-100 text-slate-900 rounded-bl-md"
                      }`}
                    >
                      {message.text}
                    </div>

                    {/* Timestamp */}
                    <div className="text-[10px] text-slate-400 mt-1">
                      {message.timestamp}
                    </div>
                  </div>
                ))}
              </div>
              

                {/* Input */}
                <div className="p-4 border-t border-slate-200">
                  <div className="flex space-x-3">
                    <input
                      value={input}
                      onChange={(e) => setInput(e.target.value)}
                      onKeyPress={(e) => e.key === "Enter" && handleSend()}
                      placeholder="Type your message..."
                      className="flex-1 px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all"
                    />
                    <button
                      onClick={handleSend}
                      className="bg-blue-600 hover:bg-blue-700 text-white p-2 rounded-lg transition-colors"
                    >
                      <Send className="w-5 h-5" />
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <div className="bg-white rounded-xl shadow-sm border border-slate-200 h-[600px] flex items-center justify-center">
                <div className="text-center">
                  <MessageCircle className="w-16 h-16 text-slate-300 mx-auto mb-4" />
                  <h3 className="text-lg font-medium text-slate-900 mb-2">
                    No active chat
                  </h3>
                  <p className="text-slate-500">
                    Start a new conversation or accept an incoming request
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
