#!/usr/bin/env python3
"""
ECDH Multi-Client Chat (server & client with GUI) with rate limiting and simple authentication handshake

Run this script on each machine. It automatically tries to connect
on localhost:65432; if that fails, it starts as the server (headless).

Usage:
    python ecdh_chat_secure.py

Dependencies:
    pip install cryptography
"""
import socket
import threading
import pickle
import base64
import sys
import queue
import time
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

# ────── Configuration ─────────────────────────────────────────
PORT = 65432                # Port for server and client communication
BUFFER_SIZE = 4096          # Socket buffer size in bytes
AUTH_TOKEN = b"supersecret"  # Shared secret for simple authentication handshake
RATE_LIMIT = 20             # max messages per window
RATE_WINDOW = 1.0           # window size in seconds

# ────── Crypto Helpers ─────────────────────────────────────────

def generate_key_pair():
    return ec.generate_private_key(ec.SECP256R1())


def serialize_public_key(pub):
    return pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_public_key(data):
    return serialization.load_der_public_key(data)


def derive_fernet_key(shared_secret):
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
    with clients_lock:
        user_list = list(clients.keys())
    packet = pickle.dumps({"type": "user_list", "users": user_list})
    with clients_lock:
        for conn, _ in clients.values():
            try:
                conn.sendall(packet)
            except Exception:
                pass


def _do_auth(conn, client_id):
    """
    Perform the initial auth handshake on the server side.
    Returns True if the token matches AUTH_TOKEN, False otherwise.
    """
    try:
        data = conn.recv(BUFFER_SIZE)
        msg = pickle.loads(data)
        if msg.get("type") != "auth" or msg.get("token") != AUTH_TOKEN:
            print(f"[SERVER] Auth failed for {client_id}")
            conn.close()
            return False
    except Exception:
        conn.close()
        return False

    # If we get here, auth succeeded
    print(f"[SERVER] Client {client_id} connected")
    return True

def handle_client(conn, addr, client_id):
    print(f"[SERVER] Client {client_id} connected from {addr}")
    # Authentication handshake
    try:
        data = conn.recv(BUFFER_SIZE)
        msg = pickle.loads(data)
        if msg.get("type") != "auth" or msg.get("token") != AUTH_TOKEN:
            print(f"[SERVER] Auth failed for {addr}")
            conn.close()
            return
    except Exception:
        conn.close()
        return

    with clients_lock:
        clients[client_id] = (conn, addr)
    conn.sendall(pickle.dumps({"type": "welcome", "your_id": client_id, "users": list(clients.keys())}))
    broadcast_user_list()

    window_start = time.time()
    msg_count = 0

    try:
        while True:
            now = time.time()
            if now - window_start > RATE_WINDOW:
                window_start = now
                msg_count = 0

            data = conn.recv(BUFFER_SIZE)
            if not data:
                break

            msg_count += 1
            if msg_count > RATE_LIMIT:
                continue

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
shared = {}
sent_keys = set()
priv = None
pub_bytes = None
sock = None
queue_events = queue.Queue()


def network_listener(sock):
    global client_id
    while True:
        data = sock.recv(BUFFER_SIZE)
        if not data:
            break
        msg = pickle.loads(data)
        mtype = msg.get("type")
        if mtype == "welcome":
            client_id = msg.get("your_id")
            queue_events.put(("welcome", msg.get("users")))
        elif mtype == "user_list":
            queue_events.put(("user_list", msg.get("users")))
        elif mtype == "key_exchange":
            sender = msg.get("from")
            their_pub = load_public_key(msg.get("pub_bytes"))
            shared_secret = priv.exchange(ec.ECDH(), their_pub)
            shared[sender] = shared_secret
            queue_events.put(("key_ok", sender))
            if sender not in sent_keys:
                sock.sendall(pickle.dumps({
                    "type": "key_exchange",
                    "from": client_id,
                    "to": sender,
                    "pub_bytes": pub_bytes
                }))
                sent_keys.add(sender)
        elif mtype == "secure_message":
            sender = msg.get("from")
            token = msg.get("token")
            if sender in shared:
                fkey = derive_fernet_key(shared[sender])
                plaintext = Fernet(fkey).decrypt(token).decode()
                queue_events.put(("msg", sender, plaintext))
    queue_events.put(("disconnect", None))


def start_gui():
    global priv, pub_bytes, sock
    # Prompt for auth token
    root = tk.Tk()
    root.withdraw()
    token = simpledialog.askstring("Auth", "Enter shared auth token:", show="*")
    if token is None:
        sys.exit(0)
    token = token.encode()
    root.destroy()

    priv = generate_key_pair()
    pub_bytes = serialize_public_key(priv.public_key())

    sock = socket.socket()
    sock.connect(('localhost', PORT))
    sock.sendall(pickle.dumps({"type": "auth", "token": token}))
    threading.Thread(target=network_listener, args=(sock,), daemon=True).start()

    # Build GUI
    gui = tk.Tk()
    gui.title("ECDH Chat")

    left = tk.Frame(gui)
    left.pack(side=tk.LEFT, fill=tk.Y)
    tk.Label(left, text="Peers").pack()
    lb = tk.Listbox(left)
    lb.pack(fill=tk.Y, expand=True)

    mid = tk.Frame(gui)
    mid.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    txt = scrolledtext.ScrolledText(mid, state='disabled')
    txt.pack(fill=tk.BOTH, expand=True)

    bot = tk.Frame(gui)
    bot.pack(side=tk.BOTTOM, fill=tk.X)
    entry = tk.Entry(bot)
    entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
    btn_send = tk.Button(bot, text="Send")
    btn_send.pack(side=tk.RIGHT)
    btn_key = tk.Button(bot, text="Key Exch")
    btn_key.pack(side=tk.RIGHT)

    def on_select(event=None):
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
        sel = lb.curselection()
        if not sel:
            return
        peer = lb.get(sel[0])
        msg = entry.get().strip()
        if not msg:
            messagebox.showwarning("Warning", "Cannot send empty message.")
            return
        entry.delete(0, tk.END)
        token = Fernet(derive_fernet_key(shared[peer])).encrypt(msg.encode())
        sock.sendall(pickle.dumps({"type": "secure_message", "from": client_id, "to": peer, "token": token}))
        txt.config(state='normal')
        txt.insert(tk.END, f"Sent to {peer}: {msg}\n")
        txt.config(state='disabled')

    def on_key():
        sel = lb.curselection()
        if not sel:
            return
        peer = lb.get(sel[0])
        if peer in shared:
            messagebox.showinfo("Info", f"Key already established with {peer}.")
            on_select()
            return
        sock.sendall(pickle.dumps({"type": "key_exchange", "from": client_id, "to": peer, "pub_bytes": pub_bytes}))
        sent_keys.add(peer)

    btn_send.config(command=on_send)
    btn_key.config(command=on_key)
    btn_send.config(state=tk.DISABLED)
    btn_key.config(state=tk.DISABLED)

    def poll():
        while not queue_events.empty():
            ev = queue_events.get()
            if ev[0] == 'welcome':
                for p in ev[1]:
                    if p != client_id:
                        lb.insert(tk.END, p)
                gui.title(f"ECDH Chat - {client_id}")
            elif ev[0] == 'user_list':
                lb.delete(0, tk.END)
                for p in ev[1]:
                    if p != client_id:
                        lb.insert(tk.END, p)
            elif ev[0] == 'key_ok':
                peer = ev[1]
                key = derive_fernet_key(shared[peer]).decode()
                txt.config(state='normal')
                txt.insert(tk.END, f"Key established with {peer}, key: {key}\n")
                txt.config(state='disabled')
                on_select()
            elif ev[0] == 'msg':
                _, sender, plaintext = ev
                txt.config(state='normal')
                txt.insert(tk.END, f"Received from {sender}: {plaintext}\n")
                txt.config(state='disabled')
            elif ev[0] == 'disconnect':
                messagebox.showinfo("Disconnected", "Server closed the connection.")
                gui.quit()
        gui.after(100, poll)

    gui.after(100, poll)
    gui.mainloop()

if __name__ == '__main__':
    try:
        start_gui()
    except (ConnectionRefusedError, OSError):
        run_server()