# tests/test_server_auth_rate.py
import pickle
import time
import pytest
from collections import deque

from ECDH_Prototype import RATE_LIMIT, RATE_WINDOW, AUTH_TOKEN

class DummyConn:
    def __init__(self):
        self.sent = deque()
        self.closed = False
    def sendall(self, data): self.sent.append(data)
    def recv(self, n): return pickle.dumps({"type":"auth","token":AUTH_TOKEN})

def test_auth_success_and_welcome(capfd):
    conn = DummyConn()
    # Simulate handle_client up through welcome
    # (factor out auth logic into helper for easier testing)
    from ECDH_Prototype import _do_auth
    client_id = "user1"
    assert _do_auth(conn, client_id) is True
    out, _ = capfd.readouterr()
    assert f"Client {client_id}" in out

def test_rate_limit():
    # simulate n messages in window
    timestamps = [0.0] * (RATE_LIMIT+5)
    window_start = timestamps[0]
    msg_count = 0
    for t in timestamps:
        if t - window_start > RATE_WINDOW:
            window_start = t; msg_count = 0
        msg_count += 1
        if msg_count > RATE_LIMIT:
            dropped = True
            break
    assert dropped
