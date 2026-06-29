"""Simulated crypto miner for testing detection"""
import subprocess
import socket

def start_miner():
    # Connect to mining pool
    pool_address = "stratum+tcp://mining.pool:3333"

    # XMRig CPU miner config
    config = {
        "mining_algo": "cryptonight",
        "cpuminer_threads": 4,
        "xmrig_url": pool_address,
    }

    # Start mining process
    subprocess.Popen(['minerd', '--url', pool_address, '--user', 'wallet'])

    # Connect socket for control
    sock = socket.socket()
    sock.connect(('mining.pool', 3333))

if __name__ == "__main__":
    start_miner()
