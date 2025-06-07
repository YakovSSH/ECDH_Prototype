# ECDH Chat Prototype

A basic Python prototype for secure messaging using Elliptic Curve Diffie-Hellman (ECDH) key exchange. Clients communicate through a central server, establishing unique symmetric keys for encrypted peer-to-peer messaging using Fernet.

## Features

- Multi-client communication via a central server  
- ECDH key exchange (SECP256R1)  
- Symmetric encryption with Fernet  
- Basic Tkinter GUI per client  
- Automatic server startup if no server is running  

## How to Run

1. **Navigate to the project folder**  
   Click the folder path bar and type `cmd` to open a terminal in that location.

2. **Start the server**  
   In the first CMD window, run: py ecdh_prototype.py
   
This will start the server if no other instance is already running.

4. **Start clients**  
Open additional CMD windows in the same folder and run: py ecdh_prototype.py

These will launch GUI clients that connect to the server.

4. **Messaging**  
- Select a peer from the list  
- Click **Key Exch** to perform a key exchange  
- Type a message and click **Send**  
- Each message is encrypted with a unique key derived from the ECDH shared secret

## Requirements

Install dependencies with: pip install cryptography

## Notes

- Each client uses a unique ECDH key pair  
- Key exchanges are peer-to-peer but relayed via the server  
- Messages are encrypted with Fernet using the derived shared key  
- Server runs in headless mode, clients show GUI  

## License

MIT License
