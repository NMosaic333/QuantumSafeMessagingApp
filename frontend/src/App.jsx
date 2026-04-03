import React, { useState, useEffect } from "react";
import ChatPage from "./pages/ChatPage";
import { MessageCircle } from "lucide-react";

// Get API URL from environment or use localhost as fallback
const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

function App() {
  const [userId, setUserId] = useState("");
  const [token, setToken] = useState("");
  const [password, setPassword] = useState("");
  const [socket, setSocket] = useState(null);
  const [inputValue, setInputValue] = useState("");
  const [loading, setLoading] = useState(false);
  const [isRegistering, setIsRegistering] = useState(true);

  const handleAuth = async () => {
    if (!inputValue.trim() || !password.trim()) return;
    setLoading(true);

    try {
      const endpoint = isRegistering ? "register" : "login";
      const response = await fetch(`${API_URL}/${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: inputValue.trim(), password }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        alert("Error: " + (errorData.detail || "Authentication failed"));
        setLoading(false);
        return;
      }

      const data = await response.json();

      setUserId(inputValue.trim());
      setToken(data.token); // Store the token from login response
    } catch (error) {
      console.error("❌ Error during auth:", error);
      alert("Network error. Check if backend is running on " + API_URL);
    } finally {
      setLoading(false);
    }
  };

  // connect websocket when userId and token are set
  useEffect(() => {
    if (userId && token) {
      const wsProtocol = API_URL.startsWith("https") ? "wss" : "ws";
      const wsUrl = API_URL.replace(/^https?/, wsProtocol);
      const newSocket = new WebSocket(`${wsUrl}/ws/${userId}?token=${token}`);
      newSocket.onopen = () => console.log("✅ WebSocket connected as", userId);
      newSocket.onclose = () => console.log("❌ WebSocket disconnected");
      newSocket.onerror = (error) => console.error("WebSocket error:", error);
      setSocket(newSocket);
      return () => newSocket.close();
    }
  }, [userId, token]);

  if (!userId) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center">
        <div className="bg-white rounded-2xl shadow-xl p-8 w-full max-w-md">
          <div className="text-center mb-6">
            <div className="bg-blue-600 rounded-full p-3 w-16 h-16 mx-auto mb-4">
              <MessageCircle className="w-10 h-10 text-white" />
            </div>
            <h2 className="text-2xl font-bold text-slate-900 mb-2">
              {isRegistering ? "Create your SecureChat account" : "Welcome back!"}
            </h2>
            <p className="text-slate-600">
              {isRegistering ? "Register to start chatting securely." : "Login to continue."}
            </p>
          </div>

          <div className="space-y-4">
            <input
              type="text"
              placeholder="Username"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              className="w-full px-4 py-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all text-center"
            />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-4 py-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all text-center"
            />

            <button
              onClick={handleAuth}
              disabled={loading}
              className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-slate-300 text-white font-medium py-3 px-4 rounded-lg transition-colors"
            >
              {loading
                ? "Please wait..."
                : isRegistering
                ? "Register & Join SecureChat"
                : "Login"}
            </button>

            <p
              onClick={() => setIsRegistering(!isRegistering)}
              className="text-sm text-blue-600 hover:underline text-center cursor-pointer"
            >
              {isRegistering ? "Already have an account? Login" : "New user? Register"}
            </p>
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

  return <ChatPage socket={socket} userId={userId} token={token} />;
}

export default App;
