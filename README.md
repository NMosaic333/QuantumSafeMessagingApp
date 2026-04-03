# 🔐 QuantumSafeMessagingApp

A real-time chat application fortified with post-quantum cryptography to ensure your communications remain secure against future quantum computing threats.

---

## ✨ Features

- **🌐 Real-time Communication**: Instant messaging between two clients using WebSockets
- **🔒 Quantum-Safe Encryption**: Protected against quantum computing attacks using:
  - **CRYSTALS-KYBER**: Post-quantum key exchange mechanism
  - **FALCON**: Quantum-resistant digital signatures for authentication
  - **AES**: Advanced encryption for message content
- **⚡ Peer-to-Peer Architecture**: Direct communication between clients
- **🛡️ Secure Storage**: Client-side encrypted data management

---

## 🏗️ Project Architecture

```
ipd-project/
├── backend/                 # Python Flask server
│   └── app/
│       ├── __init__.py
│       └── main.py
└── frontend/                # React + Vite application
    ├── src/
    │   ├── pages/
    │   │   └── ChatPage.jsx
    │   ├── utilities/
    │   │   ├── cryptomanager.js
    │   │   ├── cryptoUtils.js
    │   │   ├── secureStorage.js
    │   │   └── db.ts
    │   ├── App.jsx
    │   ├── main.jsx
    │   └── assets/
    ├── public/
    ├── package.json
    ├── vite.config.js
    └── eslint.config.js
```

---

## 🚀 Quick Start

### Prerequisites

- **Backend**: Python 3.8+, pip
- **Frontend**: Node.js 16+, npm
- **System**: Windows, macOS, or Linux

### 1. Setup Environment Files

```bash
cd backend
cp .env.example .env
# Edit .env and set DATABASE_URL if using custom database

cd ../frontend
cp .env.example .env
# Keep defaults or customize VITE_API_URL
```

### 2. Install Dependencies

**Backend:**
```bash
cd backend
pip install -r requirements.txt
```

**Frontend:**
```bash
cd frontend
npm install
```

### 3. Run the Application

**Backend (Terminal 1):**
```bash
cd backend
python -m app.main
```

**Frontend (Terminal 2):**
```bash
cd frontend
npm run dev
```

Open your browser to `http://localhost:5173` and start chatting securely!

---

## 🔐 Cryptography Overview

### Key Exchange: CRYSTALS-KYBER
Establishes a shared secret between clients resistant to quantum computing attacks.

### Digital Signatures: FALCON
Authenticates messages and prevents impersonation attacks with quantum-resistant signatures.

### Encryption: AES
Encrypts message content using the shared secret derived from KYBER key exchange.

---

## 📖 Usage

1. **Start the backend server** (see Backend Setup above)
2. **Launch the frontend application** (see Frontend Setup above)
3. **Connect two clients** to the same server
4. **Start chatting securely** - all messages are encrypted end-to-end

---

## � Security

**This application is security-hardened with post-quantum cryptography and multiple attack mitigations.** See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for details.

**⚠️ IMPORTANT FOR PRODUCTION:** Enable HTTPS/WSS before deploying. See [docs/DEPLOYMENT_HTTPS.md](docs/DEPLOYMENT_HTTPS.md).

---

## �🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python, Flask |
| Frontend | React, Vite |
| Real-time Communication | WebSockets |
| Post-Quantum Cryptography | CRYSTALS-KYBER, FALCON |
| Encryption | AES-256 |
| Build Tool | Vite |
| Linting | ESLint |

---

## 📝 Development

### Running Tests
*(Add test commands once tests are implemented)*

### Code Quality
ESLint is configured for frontend code quality checks. Run:
```bash
npm run lint
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

---

## 📄 License

This project is licensed under the MIT License. See the LICENSE file for details.

---

## ⚠️ Security Notice

This application uses post-quantum cryptographic algorithms for enhanced security against future quantum threats. However, no system is 100% secure. Always follow best practices for secure communication.

## 🚀 Deployment

### Development

```bash
# Backend (port 8000)
cd backend && python -m app.main

# Frontend (port 5173)
cd frontend && npm run dev
```

### Production: Ubuntu/Debian + Nginx (Recommended)

**One-command setup with automated SSL/TLS:**

```bash
# On your Ubuntu/Debian server (as root or with sudo):
sudo bash setup-https-ubuntu.sh yourdomain.com admin@yourdomain.com
```

**What it does automatically:**
- ✅ Installs Nginx, certbot, Python dependencies
- ✅ Obtains free SSL certificate from Let's Encrypt
- ✅ Configures HTTPS/WSS with security headers
- ✅ Creates systemd service for backend auto-start
- ✅ Sets up auto-renewal of certificates
- ✅ Configures reverse proxy for frontend

**Then deploy your frontend:**
```bash
cd frontend
npm install && npm run build
sudo cp -r dist/* /var/www/securechat/
```

**Full guides:**
- 📖 [Quick Setup Guide](docs/SETUP_UBUNTU_NGINX.md) - Step-by-step instructions
- 📋 [Deployment Checklist](docs/DEPLOYMENT_CHECKLIST.md) - Pre/post deployment steps
- 🔒 [HTTPS/WSS Deployment Guide](docs/DEPLOYMENT_HTTPS.md) - All platform options

---

## 📚 Documentation

- [README.md](README.md) - Project overview (this file)
- [SECURITY_AUDIT.md](SECURITY_AUDIT.md) - Security findings and fixes
- [docs/SECURITY_FIXES_SUMMARY.md](docs/SECURITY_FIXES_SUMMARY.md) - What was fixed
- [docs/SETUP_UBUNTU_NGINX.md](docs/SETUP_UBUNTU_NGINX.md) - Ubuntu/Debian + Nginx setup (Recommended)
- [docs/DEPLOYMENT_CHECKLIST.md](docs/DEPLOYMENT_CHECKLIST.md) - Pre/post deployment checklist
- [docs/DEPLOYMENT_HTTPS.md](docs/DEPLOYMENT_HTTPS.md) - Detailed HTTPS/WSS setup for all platforms

**Created on**: April 3, 2026
