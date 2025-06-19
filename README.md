# ECDH Chat Prototype

A basic Python prototype for secure messaging using Elliptic Curve Diffie-Hellman (ECDH) key exchange. Clients communicate through a central server, establishing unique symmetric keys for encrypted peer-to-peer messaging using [Fernet](https://github.com/pyca/cryptography/).

## Features

- Multi-client communication via a central server  
- ECDH key exchange (SECP256R1 curve)  
- Symmetric encryption with Fernet  
- Basic Tkinter GUI per client  
- Automatic headless server startup if none is running  

## How to Run

### Option 1: Manual Terminal Launch

1. **Navigate to the project folder**  
   Open a terminal in that directory (e.g., click the path bar, type `cmd`, and press Enter).

2. **Start the server**  
   ```bash
   py ECDH_Prototype.py
   ```
   This will start the server if no other instance is running.

3. **Start clients**  
   In additional terminal windows, run:
   ```bash
   py ECDH_Prototype.py
   ```
   This launches GUI clients that connect to the server.

### Option 2: Auto-launch Multiple Clients

Use the provided batch script to launch several client windows at once:

```bat
run_instances.bat <number_of_windows>
```

For example:
```bat
run_instances.bat 5
```
This opens 5 separate CMD windows, each running the GUI client.

## Messaging

1. Select a peer from the **Peers** list.  
2. Click **Key Exch** to perform an ECDH key exchange.  
3. Type a message and click **Send**.  
4. Messages are encrypted with a unique key derived from the ECDH shared secret.

## Requirements

Install dependencies with:

```bash
pip install cryptography
```

## Notes

- Each client uses its own ECDH key pair.  
- Key exchanges are relayed via the server but executed peer-to-peer.  
- Messages use Fernet encryption for confidentiality and integrity.  
- The server runs headless; clients display a GUI.

## License

MIT License
