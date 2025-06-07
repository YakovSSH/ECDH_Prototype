#!/usr/bin/env python3
"""
ECDH Multi-Client Chat (server & client with GUI)

Run this script on each machine. It automatically tries to connect
on localhost:65432; if that fails, it starts as the server (headless).

Usage:
    python ecdh_prototype.py

Dependencies:
    pip install cryptography

This script implements:
 - A headless server that relays ECDH key exchanges and encrypted messages
 - A Tkinter-based GUI client for peer-to-peer secure messaging
 - ECDH key exchange using SECP256R1 curve
 - Message encryption/decryption with Fernet (derived from ECDH shared secret)
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
PORT = 65432                # Network port for server and clients
BUFFER_SIZE = 4096          # Socket buffer size in bytes

# ────── Crypto Helpers ─────────────────────────────────────────
def generate_key_pair():
    """
    Generate an ECDH private key using the SECP256R1 curve.

    Returns:
        EllipticCurvePrivateKey: The generated private key.
    """
    return ec.generate_private_key(ec.SECP256R1())


def serialize_public_key(pub):
    """
    Serialize an EC public key to DER format bytes.

    Args:
        pub (EllipticCurvePublicKey): Public key to serialize.

    Returns:
        bytes: DER-encoded public key.
    """
    return pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_public_key(data):
    """
    Load a public key from DER-encoded bytes.

    Args:
        data (bytes): DER-encoded public key data.

    Returns:
        EllipticCurvePublicKey: The deserialized public key.
    """
    return serialization.load_der_public_key(data)


def derive_fernet_key(shared):
    """
    Derive a symmetric key for Fernet from the raw ECDH shared secret.

    Args:
        shared (bytes): Raw ECDH shared secret.

    Returns:
        bytes: URL-safe Base64-encoded 32-byte key for Fernet.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecdh chat gui'
    )
    key = hkdf.derive(shared)
    return base64.urlsafe_b64encode(key)

# ────── Server (headless) ──────────────────────────────────────
clients = {}               # Mapping of client_id -> (connection, address)
clients_lock = threading.Lock()
next_id = 1                # Incremental counter for assigning client IDs


def broadcast_user_list():
    """
    Send the updated list of connected client IDs to every client.
    """
    with clients_lock:
        users = list(clients.keys())
    pkt = pickle.dumps({"type": "user_list", "users": users})
    with clients_lock:
        for conn, _ in clients.values():
            try:
                conn.sendall(pkt)
            except Exception:
                pass


def handle_client(conn, addr, cid):
    """
    Handle messages for a single client connection.

    Args:
        conn (socket.socket): The client's socket.
        addr (tuple): Remote address (host, port).
        cid (str): Assigned client ID string.
    """
    global clients
    print(f"[SERVER] Connect {cid} from {addr}")
    with clients_lock:
        clients[cid] = (conn, addr)
    conn.sendall(pickle.dumps({"type": "welcome", "your_id": cid, "users": list(clients.keys())}))
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
            clients.pop(cid, None)
        broadcast_user_list()
        conn.close()
        print(f"[SERVER] {cid} left")


def run_server():
    """
    Start the headless server, listening for incoming client connections.
    """
    global next_id
    print(f"[SERVER] Hosting port {PORT}")
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
        print("[SERVER] shutdown")
    finally:
        server_sock.close()
        sys.exit(0)

# ────── Client with GUI ────────────────────────────────────────
client_id = None
peers = []
shared = {}
sent_keys = set()
priv = None
pub_bytes = None
sock = None
queue_events = queue.Queue()


def network_listener(s):
    """
    Background thread to listen for server messages and enqueue GUI events.

    Args:
        s (socket.socket): Connected client socket.
    """
    global client_id, peers
    while True:
        data = s.recv(BUFFER_SIZE)
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
            if sender not in sent_keys:
                s.sendall(pickle.dumps({"type": "key_exchange","from": client_id,"to": sender,"pub_bytes": pub_bytes}))
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
    Initialize keys, connect to server, and start the Tkinter GUI loop.
    """
    global priv, pub_bytes, sock
    priv = generate_key_pair()
    pub_bytes = serialize_public_key(priv.public_key())
    sock = socket.socket()
    sock.connect(('localhost', PORT))
    threading.Thread(target=network_listener, args=(sock,), daemon=True).start()

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

    def on_send():
        sel = lb.curselection()
        if not sel:
            return
        peer = lb.get(sel[0])
        if peer not in shared:
            messagebox.showwarning("Error", "Perform key exchange first")
            return
        msg = entry.get().strip()
        entry.delete(0, tk.END)
        token = Fernet(derive_fernet_key(shared[peer])).encrypt(msg.encode())
        sock.sendall(pickle.dumps({"type": "secure_message","from": client_id,"to": peer,"token": token}))
        txt.config(state='normal')
        txt.insert(tk.END, f"Sent to {peer}: {msg}\n")
        txt.config(state='disabled')

    def on_key():
        sel = lb.curselection()
        if not sel:
            return
        peer = lb.get(sel[0])
        if peer in peers:
            sock.sendall(pickle.dumps({"type": "key_exchange","from": client_id,"to": peer,"pub_bytes": pub_bytes}))
            sent_keys.add(peer)

    btn_send.config(command=on_send)
    btn_key.config(command=on_key)

    def poll():
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
                k = derive_fernet_key(shared[ev[1]]).decode()
                txt.config(state='normal')
                txt.insert(tk.END, f"Key established with {ev[1]}, the key is: {k}\n")
                txt.config(state='disabled')
            elif ev[0] == 'msg':
                sender, plaintext = ev[1], ev[2]
                txt.config(state='normal')
                txt.insert(tk.END, f"Sent from {sender}: {plaintext}\n")
                txt.config(state='disabled')
            elif ev[0] == 'disconnect':
                messagebox.showinfo("Disconnected", "Server closed")
                root.quit()
        root.after(100, poll)

    root.after(100, poll)
    root.mainloop()

if __name__ == '__main__':
    try:
        start_gui()
    except (ConnectionRefusedError, OSError):
        run_server()
