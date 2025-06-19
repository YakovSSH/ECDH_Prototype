#!/usr/bin/env python3
"""
ECDH Multi-Client Chat (server & client with GUI)

Run this script on each machine. It automatically tries to connect
on localhost:65432; if that fails, it starts as the server (headless).

Usage:
    python ecdh_chat.py

Dependencies:
    pip install cryptography

This script implements:
 - A headless server that relays ECDH key exchanges and encrypted messages between clients
 - A Tkinter-based GUI client for peer-to-peer secure messaging
 - ECDH key exchange using the SECP256R1 curve
 - Symmetric encryption/decryption via Fernet, with keys derived from the ECDH shared secret
"""
import socket
import threading
import pickle
import base64
import sys
import queue
import tkinter as tk
from tkinter import scrolledtext, messagebox

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

# ────── Configuration ─────────────────────────────────────────
PORT = 65432                # Port for server and client communication
BUFFER_SIZE = 4096          # Socket buffer size in bytes

# ────── Crypto Helpers ─────────────────────────────────────────

def generate_key_pair():
    """
    Generate an ECDH private key using the SECP256R1 curve.
    Returns:
        EllipticCurvePrivateKey: Newly generated private key.
    """
    return ec.generate_private_key(ec.SECP256R1())


def serialize_public_key(pub):
    """
    Serialize an EC public key to DER format bytes for network transmission.
    Args:
        pub (EllipticCurvePublicKey): Public key to serialize.
    Returns:
        bytes: DER-encoded public key bytes.
    """
    return pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_public_key(data):
    """
    Deserialize DER-encoded public key bytes back into an EC public key.
    Args:
        data (bytes): DER-encoded key bytes received over the network.
    Returns:
        EllipticCurvePublicKey: Reconstructed public key object.
    """
    return serialization.load_der_public_key(data)


def derive_fernet_key(shared_secret):
    """
    Derive a Fernet-compatible symmetric key from an ECDH shared secret.
    Args:
        shared_secret (bytes): Raw output from ECDH key exchange.
    Returns:
        bytes: URL-safe base64-encoded 32-byte key for Fernet.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecdh chat gui'
    )
    raw_key = hkdf.derive(shared_secret)
    return base64.urlsafe_b64encode(raw_key)

# ────── Server (headless relay) ─────────────────────────────────
clients = {}               # Map client_id -> (conn, addr)
clients_lock = threading.Lock()
next_id = 1                # Client ID counter

def broadcast_user_list():
    """
    Notify all connected clients of the current list of client IDs.
    """
    with clients_lock:
        user_list = list(clients.keys())
    packet = pickle.dumps({"type": "user_list", "users": user_list})
    with clients_lock:
        for conn, _ in clients.values():
            try:
                conn.sendall(packet)
            except Exception:
                pass

def handle_client(conn, addr, client_id):
    """
    Handle incoming messages from a single client, relaying key exchanges and encrypted messages.
    """
    global clients
    print(f"[SERVER] Client {client_id} connected from {addr}")
    with clients_lock:
        clients[client_id] = (conn, addr)
    # Send welcome containing assigned ID and current users
    conn.sendall(pickle.dumps({"type": "welcome", "your_id": client_id, "users": list(clients.keys())}))
    broadcast_user_list()
    try:
        while True:
            data = conn.recv(BUFFER_SIZE)
            if not data:
                break
            msg = pickle.loads(data)
            msg_type = msg.get("type")
            target = msg.get("to")
            if msg_type in ("key_exchange", "secure_message") and target:
                with clients_lock:
                    if target in clients:
                        clients[target][0].sendall(data)
    except Exception:
        pass
    finally:
        with clients_lock:
            clients.pop(client_id, None)
        broadcast_user_list()
        conn.close()
        print(f"[SERVER] Client {client_id} disconnected")

def run_server():
    """
    Start the headless relay server on the configured PORT.
    """
    global next_id
    print(f"[SERVER] Starting on port {PORT}")
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("", PORT))
    server_sock.listen()
    try:
        while True:
            conn, addr = server_sock.accept()
            cid = f"user{next_id}"
            next_id += 1
            threading.Thread(target=handle_client, args=(conn, addr, cid), daemon=True).start()
    except KeyboardInterrupt:
        print("[SERVER] Shutting down")
    finally:
        server_sock.close()
        sys.exit(0)

# ────── Client GUI ──────────────────────────────────────────────
client_id = None
peers = []
shared = {}          # Map peer_id -> shared_secret bytes
sent_keys = set()    # Peers we have sent our public key to
priv = None
pub_bytes = None
sock = None
queue_events = queue.Queue()

def network_listener(sock):
    """
    Background thread listening to server messages and enqueueing GUI events.
    """
    global client_id
    while True:
        data = sock.recv(BUFFER_SIZE)
        if not data:
            break
        msg = pickle.loads(data)
        msg_type = msg.get("type")
        if msg_type == "welcome":
            client_id = msg["your_id"]
            queue_events.put(("welcome", msg["users"]))
        elif msg_type == "user_list":
            queue_events.put(("user_list", msg["users"]))
        elif msg_type == "key_exchange":
            sender = msg["from"]
            their_pub = load_public_key(msg["pub_bytes"])
            shared_secret = priv.exchange(ec.ECDH(), their_pub)
            shared[sender] = shared_secret
            queue_events.put(("key_ok", sender))
            # Respond with our public key if needed
            if sender not in sent_keys:
                sock.sendall(pickle.dumps({
                    "type": "key_exchange",
                    "from": client_id,
                    "to": sender,
                    "pub_bytes": pub_bytes
                }))
                sent_keys.add(sender)
        elif msg_type == "secure_message":
            sender = msg["from"]
            token = msg["token"]
            if sender in shared:
                fkey = derive_fernet_key(shared[sender])
                plaintext = Fernet(fkey).decrypt(token).decode()
                queue_events.put(("msg", sender, plaintext))
    queue_events.put(("disconnect", None))

def start_gui():
    """
    Initialize keys, connect to server, and launch the Tkinter GUI loop.
    """
    global priv, pub_bytes, sock
    priv = generate_key_pair()
    pub_bytes = serialize_public_key(priv.public_key())

    # Connect to server
    sock = socket.socket()
    sock.connect(('localhost', PORT))
    threading.Thread(target=network_listener, args=(sock,), daemon=True).start()

    # Build GUI layout
    root = tk.Tk()
    root.title("ECDH Chat")

    left = tk.Frame(root)
    left.pack(side=tk.LEFT, fill=tk.Y)
    tk.Label(left, text="Peers").pack()
    lb = tk.Listbox(left)
    lb.pack(fill=tk.Y, expand=True)

    mid = tk.Frame(root)
    mid.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    txt = scrolledtext.ScrolledText(mid, state='disabled')
    txt.pack(fill=tk.BOTH, expand=True)

    bot = tk.Frame(root)
    bot.pack(side=tk.BOTTOM, fill=tk.X)
    entry = tk.Entry(bot)
    entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
    btn_send = tk.Button(bot, text="Send")
    btn_send.pack(side=tk.RIGHT)
    btn_key = tk.Button(bot, text="Key Exch")
    btn_key.pack(side=tk.RIGHT)

    def on_select(event=None):
        """
        Update button states based on selected peer and whether a shared key exists.
        """
        sel = lb.curselection()
        if not sel:
            btn_key.config(state=tk.DISABLED)
            btn_send.config(state=tk.DISABLED)
            return
        peer = lb.get(sel[0])
        btn_key.config(state=tk.DISABLED if peer in shared else tk.NORMAL)
        btn_send.config(state=tk.NORMAL if peer in shared else tk.DISABLED)

    lb.bind('<<ListboxSelect>>', on_select)

    def on_send():
        """
        Encrypt and send a non-empty message to the selected peer.
        """
        sel = lb.curselection()
        if not sel:
            return
        peer = lb.get(sel[0])
        msg = entry.get().strip()
        # Prevent sending empty messages
        if not msg:
            messagebox.showwarning("Warning", "Please write something!")
            return
        entry.delete(0, tk.END)
        token = Fernet(derive_fernet_key(shared[peer])).encrypt(msg.encode())
        sock.sendall(pickle.dumps({
            "type": "secure_message",
            "from": client_id,
            "to": peer,
            "token": token
        }))
        txt.config(state='normal')
        txt.insert(tk.END, f"Sent to {peer}: {msg}\n")
        txt.config(state='disabled')

    def on_key():
        """
        Initiate ECDH key exchange with the chosen peer, if not already done.
        """
        sel = lb.curselection()
        if not sel:
            return
        peer = lb.get(sel[0])
        if peer in shared:
            messagebox.showinfo("Info", f"Key already established with {peer}.")
            on_select()
            return
        sock.sendall(pickle.dumps({
            "type": "key_exchange",
            "from": client_id,
            "to": peer,
            "pub_bytes": pub_bytes
        }))
        sent_keys.add(peer)

    btn_send.config(command=on_send)
    btn_key.config(command=on_key)
    # Both buttons start disabled until a peer is selected
    btn_send.config(state=tk.DISABLED)
    btn_key.config(state=tk.DISABLED)

    def poll():
        """
        Poll the event queue for updates from the listener thread and update the GUI.
        """
        while not queue_events.empty():
            ev = queue_events.get()
            if ev[0] == 'welcome':
                for p in ev[1]:
                    if p != client_id:
                        peers.append(p)
                        lb.insert(tk.END, p)
            elif ev[0] == 'user_list':
                nl = [u for u in ev[1] if u != client_id]
                peers[:] = nl
                lb.delete(0, tk.END)
                for p in nl:
                    lb.insert(tk.END, p)
            elif ev[0] == 'key_ok':
                peer = ev[1]
                key = derive_fernet_key(shared[peer]).decode()
                txt.config(state='normal')
                txt.insert(tk.END, f"Key established with {peer}, key: {key}\n")
                txt.config(state='disabled')
                on_select()
            elif ev[0] == 'msg':
                sender, plaintext = ev[1], ev[2]
                txt.config(state='normal')
                txt.insert(tk.END, f"Received from {sender}: {plaintext}\n")
                txt.config(state='disabled')
            elif ev[0] == 'disconnect':
                messagebox.showinfo("Disconnected", "Server closed the connection.")
                root.quit()
        root.after(100, poll)

    # Start polling and enter main loop
    root.after(100, poll)
    root.mainloop()

if __name__ == '__main__':
    try:
        start_gui()
    except (ConnectionRefusedError, OSError):
        run_server()
