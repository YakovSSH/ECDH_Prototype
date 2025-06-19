# ECDH_Prototype

A simple Python-based prototype demonstrating secure peer-to-peer messaging using Elliptic-Curve Diffie-Hellman (ECDH) for key exchange and Fernet for symmetric encryption. The project includes a headless relay server and a Tkinter GUI client that can automatically decide its role based on network availability.

---

## Features

- **Automatic Role Detection**: The first instance on the network becomes the relay server; subsequent clients connect to it automatically.
- **ECDH Key Exchange**: Uses the SECP256R1 curve to establish a shared secret between peers.
- **HKDF-Based Key Derivation**: Derives a URL-safe, Base64-encoded key for Fernet encryption.
- **Fernet Encryption**: Ensures confidentiality of all messages exchanged between clients.
- **Authentication and Rate Limiting**: Simple token-based auth with configurable rate limits to prevent abuse.
- **Unit and Integration Tests**: Cover key generation, shared-secret validation, encryption round-trips, authentication flow, and rate-limiting logic.

---

## Getting Started

### Prerequisites

- Python 3.8 or later
- [`cryptography`](https://pypi.org/project/cryptography/) library

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/YakovSSH/ECDH_Prototype.git
   cd ECDH_Prototype
   ```

2. Install dependencies:
   ```bash
   pip install cryptography
   ```

---

## Usage

Run the main script on each machine (or in separate terminals) on the same local network:

```bash
python ecdh_chat.py
```

- If this instance cannot connect to an existing server, it starts in server (relay) mode.
- Clients automatically discover and connect to the relay server.
- Peer-to-peer encrypted chat sessions begin once two clients exchange public keys.

---

## Project Structure

```
ECDH_Prototype/
├── ecdh_chat.py      # Main server/client application
├── ECDH_Prototype/   # Library code for key handling and auth
│   ├── __init__.py
│   ├── helpers.py    # Key generation and derivation functions
│   ├── server.py     # Relay server logic
│   └── client.py     # Client GUI and networking
├── tests/            # Pytest-based test suite
│   ├── test_ecdh_helpers.py
│   └── test_server_auth_rate.py
└── README.md         # This file
```

---

## Running Tests

Use `pytest` to run all unit and integration tests:

```bash
pytest
```


---

## Configuration

- **RATE_LIMIT** and **RATE_WINDOW** in `server.py` control how many messages a client can send in a given time window.
- **AUTH_TOKEN** in `helpers.py` is used for simple connection authentication.


---

## Future Work

- Add peer discovery and NAT traversal for wider network support.
- Introduce persistent storage for message history.
- Replace the simple token auth with mutual certificate validation.
- Implement group chats with separate key exchanges for each participant.

---

## License

Distributed under the MIT License. See `LICENSE` for more details.
