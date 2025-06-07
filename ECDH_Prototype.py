"""
ECDH Multi-Client Chat (server & client with GUI)

Run this script on each machine. It automatically tries to connect
on localhost:65432; if that fails, it starts as the server (headless).

Dependencies:
    pip install cryptography
"""
import socket
import threading
import pickle
import base64
import sys
import queue
import tkinter as tk
from tkinter import ttk, scrolledtext, simpledialog, messagebox

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

# ────── Configuration ─────────────────────────────────────────
PORT = 65432
BUFFER_SIZE = 4096
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

def derive_fernet_key(shared):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecdh chat gui'
    )
    key = hkdf.derive(shared)
    return base64.urlsafe_b64encode(key)

# ────── Server (headless) ──────────────────────────────────────
clients = {}
clients_lock = threading.Lock()
next_id = 1

def broadcast_user_list():
    with clients_lock:
        users = list(clients.keys())
    pkt = pickle.dumps({"type":"user_list","users":users})
    with clients_lock:
        for conn, _ in clients.values():
            try: conn.sendall(pkt)
            except: pass

def handle_client(conn, addr, cid):
    global clients
    print(f"[SERVER] Connect {cid} from {addr}")
    with clients_lock:
        clients[cid] = (conn, addr)
        users = list(clients.keys())
    # send welcome + list
    conn.sendall(pickle.dumps({"type":"welcome","your_id":cid,"users":users}))
    broadcast_user_list()
    try:
        while True:
            data = conn.recv(BUFFER_SIZE)
            if not data: break
            msg = pickle.loads(data)
            t = msg.get("type"); to = msg.get("to")
            if t in ("key_exchange","secure_message") and to:
                with clients_lock:
                    if to in clients:
                        clients[to][0].sendall(data)
    except: pass
    finally:
        with clients_lock: del clients[cid]
        broadcast_user_list()
        conn.close(); print(f"[SERVER] {cid} left")

def run_server():
    global next_id
    print(f"[SERVER] Hosting port {PORT}")
    sv = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sv.bind(("",PORT)); sv.listen()
    try:
        while True:
            c,a = sv.accept()
            cid = f"user{next_id}"; next_id+=1
            threading.Thread(target=handle_client,args=(c,a,cid),daemon=True).start()
    except KeyboardInterrupt: print("[SERVER] shutdown")
    finally: sv.close(); sys.exit(0)

# ────── Client with GUI ────────────────────────────────────────
client_id=None; peers=[]; shared={} ; sent_keys=set()
priv=None; pub_bytes=None; sock=None
queue_events = queue.Queue()

def network_listener(s):
    """Listen and enqueue events for GUI"""
    global client_id, peers
    while True:
        data = s.recv(BUFFER_SIZE)
        if not data: break
        msg = pickle.loads(data); t=msg.get("type")
        if t=="welcome":
            client_id=msg['your_id']
            queue_events.put(("welcome",msg['users']))
        elif t=="user_list":
            queue_events.put(("user_list",msg['users']))
        elif t=="key_exchange":
            frm=msg['from']; their=load_public_key(msg['pub_bytes'])
            shared[frm]=priv.exchange(ec.ECDH(),their)
            queue_events.put(("key_ok",frm))
            if frm not in sent_keys:
                s.sendall(pickle.dumps({"type":"key_exchange","from":client_id,"to":frm,"pub_bytes":pub_bytes}))
                sent_keys.add(frm)
        elif t=="secure_message":
            frm=msg['from']; tok=msg['token']
            if frm in shared:
                pt=Fernet(derive_fernet_key(shared[frm])).decrypt(tok).decode()
                queue_events.put(("msg",frm,pt))
    queue_events.put(("disconnect",None))

def start_gui():
    global priv,pub_bytes,sock
    priv=generate_key_pair(); pub_bytes=serialize_public_key(priv.public_key())
    sock=socket.socket(); sock.connect(('localhost',PORT))
    threading.Thread(target=network_listener,args=(sock,),daemon=True).start()
    # build UI
    root=tk.Tk(); root.title(f"ECDH Chat")
    # peers list
    left=tk.Frame(root); left.pack(side=tk.LEFT,fill=tk.Y)
    lbl=tk.Label(left,text="Peers"); lbl.pack()
    lb=tk.Listbox(left); lb.pack(fill=tk.Y,expand=True)
    # chat area
    mid=tk.Frame(root); mid.pack(side=tk.LEFT,fill=tk.BOTH,expand=True)
    txt=scrolledtext.ScrolledText(mid,state='disabled'); txt.pack(fill=tk.BOTH,expand=True)
    # entry
    bot=tk.Frame(root); bot.pack(side=tk.BOTTOM,fill=tk.X)
    entry=tk.Entry(bot); entry.pack(side=tk.LEFT,fill=tk.X,expand=True)
    btn_send=tk.Button(bot,text="Send")
    btn_send.pack(side=tk.RIGHT)
    btn_key=tk.Button(bot,text="Key Exch")
    btn_key.pack(side=tk.RIGHT)
    # actions
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
        sock.sendall(pickle.dumps({
            "type": "secure_message",
            "from": client_id,
            "to": peer,
            "token": token
        }))

        # display outgoing with “sent to”
        txt.config(state='normal')
        txt.insert(tk.END, f"Sent to {peer}: {msg}\n")
        txt.config(state='disabled')
    def on_key():
        sel=lb.curselection()
        if not sel: return
        peer=lb.get(sel[0])
        if peer in peers:
            sock.sendall(pickle.dumps({"type":"key_exchange","from":client_id,"to":peer,"pub_bytes":pub_bytes}))
            sent_keys.add(peer)
    btn_send.config(command=on_send); btn_key.config(command=on_key)
    # event loop
    def poll():
        while not queue_events.empty():
            ev=queue_events.get()
            if ev[0]=='welcome':
                for p in ev[1]:
                    if p!=client_id: peers.append(p); lb.insert(tk.END,p)
            elif ev[0]=='user_list':
                nl=[u for u in ev[1] if u!=client_id]
                peers[:] = nl; lb.delete(0,tk.END)
                for p in nl: lb.insert(tk.END,p)
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
            elif ev[0]=='disconnect': messagebox.showinfo("Disconnected","Server closed"); root.quit()
        root.after(100,poll)
    root.after(100,poll)
    root.mainloop()

# ────── Entry ──────────────────────────────────────────────────
if __name__=='__main__':
    try: start_gui()
    except (ConnectionRefusedError, OSError): run_server()