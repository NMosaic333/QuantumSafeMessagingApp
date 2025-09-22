from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import json

app = FastAPI()
kem_pubkeys = {}
falcon_pubkeys = {}  # user_id -> Falcon public key (Uint8Array as list)
# Allow CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # replace with frontend URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory stores
connections = {}   # user_id -> websocket

# WebSocket endpoint for messaging and PQC key exchange
@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str):
    await websocket.accept()
    connections[user_id] = websocket
    print(f"{user_id} connected.")

    try:
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)

            msg_type = msg.get("type")
            recipient = msg.get("to")

            if msg_type in ["chat_request", "shared_secret", "chat"]:
                # Ensure recipient exists
                if recipient in connections:
                    await connections[recipient].send_text(data)
                    print(f"Forwarded {msg_type} from {user_id} to {recipient}")
                else:
                    print(f"Recipient {recipient} not connected. Cannot forward {msg_type}.")
            else:
                # Optional: handle other message types or broadcast
                print(f"Unknown message type: {msg_type} from {user_id}")

    except WebSocketDisconnect:
        print(f"{user_id} disconnected.")
        connections.pop(user_id, None)


# Endpoint to store frontend-generated Kyber public key
@app.post("/api/publish_kem")
async def publish_kem(request: Request):
    data = await request.json()
    user = data.get("user")
    kem_pub = data.get("kem_pub")
    falcon_pub = data.get("falcon_pub")

    if not user or not kem_pub or not falcon_pub:
        return {"status": "error", "message": "Missing user or keys"}

    kem_pubkeys[user] = kem_pub
    falcon_pubkeys[user] = falcon_pub
    print(f"✅ Stored Kyber and Falcon public keys for {user} (len={len(kem_pub)}, len={len(falcon_pub)})")

    return {"status": "success"}

# Endpoint to fetch a peer's Kyber public key
@app.get("/api/get_kyber_pub/{user_id}")
async def get_kyber_pub(user_id: str):
    if user_id not in kem_pubkeys:
        return {"status": "error", "message": "Key not found"}
    return {"status": "success", "pk": kem_pubkeys[user_id]}

# Endpoint to fetch a peer's Falcon public key
@app.get("/api/get_falcon_pub/{user_id}")
async def get_falcon_pub(user_id: str):
    if user_id not in falcon_pubkeys:
        return {"status": "error", "message": "Key not found"}
    return {"status": "success", "fk": falcon_pubkeys[user_id]}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
