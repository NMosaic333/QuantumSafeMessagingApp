import os
import json
import base64
import bcrypt
import secrets
from datetime import datetime, timedelta
from typing import Dict, List
from dotenv import load_dotenv

from fastapi import FastAPI, Depends, HTTPException, Header, WebSocket, WebSocketDisconnect, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import Column, String, DateTime, Text, create_engine, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session
import uvicorn
from slowapi import Limiter
from slowapi.util import get_remote_address
import re

# ============================================================
#                   DATABASE CONFIGURATION
# ============================================================

load_dotenv()  # Load environment variables from .env file
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable not set")
SESSION_EXPIRY_MINUTES = 60  # Session validity in minutes
PENDING_MESSAGE_EXPIRY_MINUTES = 24 * 60  # Auto-delete offline messages after 24 hours
MAX_REQUEST_SIZE = 100_000  # 100KB max request payload
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")
ALLOWED_USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_]{3,50}$")

engine = create_engine(DATABASE_URL, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_token(authorization: str = Header(None), db: Session = Depends(get_db)) -> str:
    """Verify auth token from Authorization header. Returns username if valid."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid authorization header")
    
    token = authorization.replace("Bearer ", "")
    session = db.query(SessionToken).filter(
        (SessionToken.token == token) &
        (SessionToken.expires_at > datetime.utcnow())
    ).first()
    
    if not session:
        raise HTTPException(401, "Invalid or expired token")
    
    return session.username

# ============================================================
#                   HELPER FUNCTIONS
# ============================================================

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def cleanup_expired_messages(db: Session):
    """Delete pending messages older than PENDING_MESSAGE_EXPIRY_MINUTES"""
    expiry_time = datetime.utcnow() - timedelta(minutes=PENDING_MESSAGE_EXPIRY_MINUTES)
    db.query(PendingMessage).filter(PendingMessage.created_at < expiry_time).delete()
    db.commit()

# ============================================================
#                   DATABASE MODELS
# ============================================================

class User(Base):
    __tablename__ = "users"
    username = Column(String(50), primary_key=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    kem_pub = Column(Text, nullable=True)                  # Kyber public key
    falcon_pub = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    sent_messages = relationship("Message", back_populates="sender", foreign_keys="Message.sender_username")
    received_messages = relationship("Message", back_populates="recipient", foreign_keys="Message.recipient_username")


class Message(Base):
    __tablename__ = "messages"
    sender_username = Column(String(50), ForeignKey("users.username"), primary_key=True)
    recipient_username = Column(String(50), ForeignKey("users.username"), primary_key=True)
    created_at = Column(DateTime, primary_key=True, default=datetime.utcnow)
    body_enc = Column(Text, nullable=False)

    sender = relationship("User", back_populates="sent_messages", foreign_keys=[sender_username])
    recipient = relationship("User", back_populates="received_messages", foreign_keys=[recipient_username])

class PendingRequest(Base):
    __tablename__ = "pending_requests"
    id = Column(String(128), primary_key=True, default=lambda: secrets.token_hex(16))
    user_id = Column(String(50), ForeignKey("users.username"), nullable=False)
    peer_id = Column(String(50), ForeignKey("users.username"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class PendingMessage(Base):
    __tablename__ = "pending_messages"
    id = Column(String(128), primary_key=True, default=lambda: secrets.token_hex(16))
    sender_id = Column(String(50), ForeignKey("users.username"), nullable=False)
    receiver_id = Column(String(50), ForeignKey("users.username"), nullable=False)
    payload = Column(Text, nullable=False)  # JSON string with ciphertext and iv
    signature = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class SessionToken(Base):
    __tablename__ = "sessions"
    token = Column(String(128), primary_key=True)
    username = Column(String(50))
    expires_at = Column(DateTime)

Base.metadata.create_all(bind=engine)

# ============================================================
#                   SCHEMAS
# ============================================================

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, regex="^[a-zA-Z0-9_]+$")
    password: str = Field(..., min_length=8, max_length=128)

class Login(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)

class MessageCreate(BaseModel):
    recipient_username: str = Field(..., min_length=3, max_length=50)
    body: str = Field(..., min_length=1, max_length=10000)

# ============================================================
#                   FASTAPI SETUP
# ============================================================

app = FastAPI(title="IPDAES + WebSocket Signaling")

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# CORS configuration - restrict to specific origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["Content-Type", "Authorization"],
)

# ============================================================
#                   STATE STORAGE (WebSocket)
# ============================================================

connected_users: Dict[str, WebSocket] = {}
peer_map: Dict[str, List[str]] = {}

# ============================================================
#                   REST ENDPOINTS (Auth + Messaging)
# ============================================================

@app.post("/register")
@limiter.limit("5/minute")
async def register(request: Request, user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(400, "username already exists")
    new_user = User(username=user.username, password_hash=hash_password(user.password))
    db.add(new_user)
    db.commit()
    return {"message": f"user {user.username} created successfully"}


@app.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, data: Login, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data.username).first()
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(401, "Invalid credentials")
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(minutes=SESSION_EXPIRY_MINUTES)
    db.add(SessionToken(token=token, username=user.username, expires_at=expires_at))
    db.commit()
    return {"token": token, "username": user.username, "expires_at": expires_at.isoformat()}


def get_user_by_token(token: str = Header(...), db: Session = Depends(get_db)) -> User:
    session = db.query(SessionToken).filter(SessionToken.token == token).first()
    if not session or session.expires_at < datetime.utcnow():
        raise HTTPException(401, "Invalid or expired token")
    user = db.query(User).filter(User.username == session.username).first()
    if not user:
        raise HTTPException(401, "User not found")
    return user


@app.post("/messages")
def send_message(msg: MessageCreate, user: User = Depends(get_user_by_token), db: Session = Depends(get_db)):
    recipient = db.query(User).filter(User.username == msg.recipient_username).first()
    if not recipient:
        raise HTTPException(404, "Recipient not found")

    # For now, just store plaintext (or you can plug in Kyber-based encryption here)
    message = Message(
        sender_username=user.username,
        recipient_username=recipient.username,
        body_enc=msg.body
    )
    db.add(message)
    db.commit()
    return {"status": "sent"}


@app.get("/messages")
def get_messages(with_username: str, user: User = Depends(get_user_by_token), db: Session = Depends(get_db)):
    other = db.query(User).filter(User.username == with_username).first()
    if not other:
        raise HTTPException(404, "User not found")
    msgs = db.query(Message).filter(
        ((Message.sender_username == user.username) & (Message.recipient_username == other.username)) |
        ((Message.sender_username == other.username) & (Message.recipient_username == user.username))
    ).order_by(Message.created_at).all()
    out = []
    for m in msgs:
        out.append({
            "sender": m.sender_username,
            "recipient": m.recipient_username,
            "body": m.body_enc,
            "created_at": m.created_at
        })
    return out

# ============================================================
#                   WEBSOCKET ENDPOINTS
# ============================================================

@app.get("/api/check-online-users/{user_id}/{peer_id}")
async def get_online_users(user_id: str, peer_id: str):
    peer_map.setdefault(user_id, []).append(peer_id)
    peer_map.setdefault(peer_id, []).append(user_id)
    return {"status": "success", "online": peer_id in connected_users}


async def broadcast_status(user_id: str, online: bool):
    if user_id not in peer_map:
        return
    notification = {"type": "status_update", "peerId": user_id, "online": online}
    for peer in peer_map[user_id]:
        if peer in connected_users:
            try:
                await connected_users[peer].send_json(notification)
            except Exception as e:
                print(f"Failed to notify {peer}: {e}")


@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str, token: str = Query(...)):
    """WebSocket endpoint with token-based authentication"""
    # Verify token before accepting connection
    db = SessionLocal()
    try:
        session = db.query(SessionToken).filter(
            (SessionToken.token == token) & 
            (SessionToken.username == user_id) &
            (SessionToken.expires_at > datetime.utcnow())
        ).first()
        if not session:
            await websocket.close(code=1008, reason="Unauthorized")
            return
    finally:
        db.close()
    
    await websocket.accept()
    connected_users[user_id] = websocket
    print(f"{user_id} connected.")
    await broadcast_status(user_id, True)

    db = None
    authenticated_user = user_id  # Store authenticated user from token
    try:
        db = SessionLocal()
        
        # Clean up expired pending messages
        cleanup_expired_messages(db)

        # ========================================
        # 1️⃣ Send pending chat requests
        # ========================================
        pending_requests = db.query(PendingRequest).filter(PendingRequest.peer_id == user_id).all()
        for req in pending_requests:
            await connected_users[req.peer_id].send_text(json.dumps({
                "type": "chat_request",
                "from": req.user_id,
                "to": req.peer_id,
            }))
            db.delete(req)
        db.commit()

        # ========================================
        # 2️⃣ Send pending messages
        # ========================================
        pending_messages = (
            db.query(PendingMessage)
            .filter(PendingMessage.receiver_id == user_id)
            .order_by(PendingMessage.created_at)
            .all()
        )
        # When reading from DB
        for msg in pending_messages:
            # If payload/signature are JSON strings, convert them to real objects
            try:
                payload = json.loads(msg.payload) if isinstance(msg.payload, str) else msg.payload
            except json.JSONDecodeError:
                payload = msg.payload

            try:
                signature = json.loads(msg.signature) if isinstance(msg.signature, str) else msg.signature
            except json.JSONDecodeError:
                signature = msg.signature

            data = {
                "type": "chat",
                "from": msg.sender_id,
                "to": msg.receiver_id,
                "payload": payload,
                "signature": signature,
            }

            await connected_users[msg.receiver_id].send_text(json.dumps(data))
            db.delete(msg)
        db.commit()

        # ========================================
        # 3️⃣ Handle incoming live messages
        # ========================================
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)
            msg_type = msg.get("type")
            recipient = msg.get("to")
            claimed_sender = msg.get("from")

            # Verify sender is claiming to be the authenticated user (prevent spoofing)
            if claimed_sender != authenticated_user:
                print(f"Message spoofing attempt: {claimed_sender} != {authenticated_user}")
                continue

            if msg_type in ["chat_request", "shared_secret", "chat"]:
                if recipient in connected_users:
                    await connected_users[recipient].send_text(data)
                else:
                    # offline → store as pending
                    if msg_type == "chat_request":
                        db.add(PendingRequest(user_id=authenticated_user, peer_id=recipient))
                    else:
                        offline_msg = PendingMessage(
                            receiver_id=recipient,
                            sender_id=authenticated_user,
                            payload=json.dumps(msg.get("payload", "")),
                            signature=msg.get("signature", "")
                        )
                        db.add(offline_msg)
                    db.commit()
            else:
                print(f"Unknown message type: {msg_type}")

    except WebSocketDisconnect:
        print(f"{authenticated_user} disconnected.")
        connected_users.pop(authenticated_user, None)
        await broadcast_status(authenticated_user, False)
        # Clean up peer map to prevent memory leak
        if authenticated_user in peer_map:
            del peer_map[authenticated_user]
        for peers in peer_map.values():
            if authenticated_user in peers:
                peers.remove(authenticated_user)
    except Exception as e:
        print(f"WebSocket error for {user_id}: {e}")
    finally:
        if db:
            db.close()

# ============================================================
#                   KYBER & FALCON KEY PUBLISHING
# ============================================================

@app.post("/api/publish_kem")
async def publish_kem(request: Request, db: Session = Depends(get_db)):
    # Check request size
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_REQUEST_SIZE:
        raise HTTPException(413, f"Payload too large. Max size: {MAX_REQUEST_SIZE} bytes")
    
    data = await request.json()
    user = data.get("user")
    kem_pub = data.get("kem_pub")
    falcon_pub = data.get("falcon_pub")

    if not user or not kem_pub or not falcon_pub:
        raise HTTPException(status_code=400, detail="Missing user or keys")

    db_user = db.query(User).filter(User.username == user).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db_user.kem_pub = kem_pub
    db_user.falcon_pub = falcon_pub
    db.commit()

    print(f"✅ Stored keys for {user} in database.")
    return {"status": "success", "message": "Keys saved successfully"}


@app.get("/api/get_kyber_pub/{user_id}")
async def get_kyber_pub(user_id: str, authenticated_username: str = Depends(verify_token), db: Session = Depends(get_db)):
    """Get Kyber public key for a user. Requires authentication to prevent user enumeration."""
    db_user = db.query(User).filter(User.username == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"status": "success", "pk": db_user.kem_pub}


@app.get("/api/get_falcon_pub/{user_id}")
async def get_falcon_pub(user_id: str, authenticated_username: str = Depends(verify_token), db: Session = Depends(get_db)):
    """Get Falcon public key for a user. Requires authentication to prevent user enumeration."""
    db_user = db.query(User).filter(User.username == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"status": "success", "fk": db_user.falcon_pub}

# ============================================================
#                   PENDING REQUESTS & MESSAGES
# ============================================================

@app.get("/api/get-pending-requests/{user_id}")
def get_pending_requests(user_id: str, db: Session = Depends(get_db)):
    requests = db.query(PendingRequest).filter(PendingRequest.user_id == user_id).all()
    peers = [r.peer_id for r in requests]
    for r in requests:
        db.delete(r)
    db.commit()
    return peers


@app.get("/api/get-pending-messages/{user_id}")
def get_pending_messages(user_id: str, db: Session = Depends(get_db)):
    messages = db.query(PendingMessage).filter(PendingMessage.user_id == user_id).order_by(PendingMessage.created_at).all()
    out = [
        {
            "id": m.id,
            "userId": m.user_id,
            "peerId": m.peer_id,
            "payload": m.payload,
            "signature": m.signature,
        }
        for m in messages
    ]
    for m in messages:
        db.delete(m)
    db.commit()
    return out


# ============================================================
#                   ROOT
# ============================================================

@app.get("/")
def read_root():
    return {"status": "running", "message": "IPDAES server active"}

# ============================================================
#                   MAIN
# ============================================================

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
