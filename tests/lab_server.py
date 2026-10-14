#!/usr/bin/env python3
"""Tiny localhost-only test servers for ssh-ident-observer.

Usage: lab_server.py MODE PORT
  ssh     sends an SSH identification string, then waits
  prelude sends two text lines, then an SSH identification string
  text    sends a non-SSH line ("220 ...")
  silent  accepts the connection and sends nothing
Binds to 127.0.0.1 only.
"""
import socket
import sys
import time

mode, port = sys.argv[1], int(sys.argv[2])
payloads = {
    "ssh": b"SSH-2.0-LabServer_1.0 lab-test\r\n",
    "prelude": b"hello from lab\r\nsecond line\r\nSSH-2.0-LabPrelude_2.1\r\n",
    "text": b"220 lab.example ESMTP ready\r\n",
    "silent": b"",
}

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(5)
while True:
    conn, _ = srv.accept()
    if payloads[mode]:
        conn.sendall(payloads[mode])
    time.sleep(8)  # keep the connection open so a silent port really times out
    conn.close()
