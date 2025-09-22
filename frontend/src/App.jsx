import React, { useState, useEffect } from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import ChatPage from "./pages/ChatPage";
import { Send, Users, MessageCircle, UserPlus, Check, X } from "lucide-react";


function App() {
  const [userId, setUserId] = useState("");
  const [socket, setSocket] = useState(null);
  const [inputValue, setInputValue] = useState("");

  // Mock socket connection for demo
  useEffect(() => {
    if (userId) {
      const newSocket = new WebSocket("ws://localhost:8000/ws/" + userId);
      setSocket(newSocket);
    }
  }, [userId]);

  if (!userId) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center">
        <div className="bg-white rounded-2xl shadow-xl p-8 w-full max-w-md">
          <div className="text-center mb-6">
            <div className="bg-blue-600 rounded-full p-3 w-16 h-16 mx-auto mb-4">
              <MessageCircle className="w-10 h-10 text-white" />
            </div>
            <h2 className="text-2xl font-bold text-slate-900 mb-2">Welcome to SecureChat</h2>
            <p className="text-slate-600">Enter your username to get started</p>
          </div>
          
          <div className="space-y-4">
            <input
              type="text"
              placeholder="Enter your username"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              className="w-full px-4 py-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all text-center"
              onKeyDown={(e) => {
                if (e.key === "Enter" && inputValue.trim()) {
                  setUserId(inputValue.trim()); // set main state on Enter
                }
              }}
            />
            <button
              onClick={() => inputValue && setUserId(inputValue.trim())}
              disabled={!inputValue}
              className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-slate-300 text-white font-medium py-3 px-4 rounded-lg transition-colors"
            >
              Join SecureChat
            </button>
          </div>

          <div className="mt-6 text-center text-sm text-slate-500">
            <p>🔒 End-to-end encrypted conversations</p>
          </div>
        </div>
      </div>
    );
  }

  if (!socket) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 flex items-center justify-center">
        <div className="bg-white rounded-2xl shadow-lg p-8 text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-slate-600">Connecting to secure servers...</p>
        </div>
      </div>
    );
  }

  return <ChatPage socket={socket} userId={userId} />;
}

export default App;
