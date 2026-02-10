#!/usr/bin/env python3

import socket
import threading
import logging
import os
import time

LOG_FILE = "/app/logs/honeypot.log"

BIND_ADDR = "0.0.0.0"
LISTEN_PORT = 22

FAKE_SSH_BANNER = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"


def init_logger():
    os.makedirs("/app/logs", exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler()
        ],
    )


def log_session(client_socket, client_address):
    logger = logging.getLogger("ssh-honeypot")
    src_ip, src_port = client_address
    session_start = time.time()

    logger.info(f"Incoming connection from {src_ip}:{src_port}")

    try:
        client_socket.sendall(FAKE_SSH_BANNER)
        client_socket.settimeout(5)

        try:
            payload = client_socket.recv(1024)
            if payload:
                decoded = payload.decode(errors="ignore").strip()
                logger.info(f"Payload from {src_ip}: {decoded}")
            else:
                logger.info(f"Empty payload from {src_ip}")
        except socket.timeout:
            logger.info(f"Timeout waiting for data from {src_ip}")

    except Exception as err:
        logger.error(f"Session error from {src_ip}: {err}")

    finally:
        client_socket.close()
        elapsed = time.time() - session_start
        logger.info(f"Session ended for {src_ip} (duration={elapsed:.2f}s)")


def start_listener():
    logger = logging.getLogger("ssh-honeypot")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((BIND_ADDR, LISTEN_PORT))
    sock.listen(10)

    logger.info(f"Honeypot active on {BIND_ADDR}:{LISTEN_PORT}")

    while True:
        client, address = sock.accept()
        worker = threading.Thread(
            target=log_session,
            args=(client, address),
            daemon=True
        )
        worker.start()


if __name__ == "__main__":
    init_logger()
    start_listener()
