#!/usr/bin/env python3

import argparse
import logging
import socket
import time
import subprocess
import threading
import select


DEFAULT_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PORT = 2222
DEFAULT_WINDOW = 10.0


def configure_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )


def forward_traffic(left, right):
    endpoints = [left, right]
    while True:
        ready, _, _ = select.select(endpoints, [], [], 30)
        if not ready:
            return
        for src in ready:
            dst = right if src is left else left
            payload = src.recv(4096)
            if not payload:
                return
            dst.sendall(payload)


def allow_ssh(port, client_ip):
    logging.info("Allowing %s access to port %s", client_ip, port)
    subprocess.run([
        "iptables",
        "-I", "INPUT",
        "-p", "tcp",
        "--dport", str(port),
        "-s", client_ip,
        "-j", "ACCEPT"
    ])


def block_ssh(port, client_ip):
    logging.info("Revoking %s access to port %s", client_ip, port)
    subprocess.run([
        "iptables",
        "-D", "INPUT",
        "-p", "tcp",
        "--dport", str(port),
        "-s", client_ip,
        "-j", "ACCEPT"
    ])


def run_knock_server(knock_ports, timeout, protected_port):
    log = logging.getLogger("KnockDaemon")
    log.info("Knock sequence: %s", knock_ports)
    log.info("Protected SSH port: %s", protected_port)

    client_state = {}

    listeners = []
    for p in knock_ports:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", p))
        srv.listen(5)
        listeners.append((p, srv))
        log.info("Listening on knock port %d", p)

    gate = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    gate.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    gate.bind(("0.0.0.0", protected_port))
    gate.listen(5)
    log.info("SSH gate active on port %d", protected_port)

    while True:
        for port, sock in listeners:
            sock.settimeout(0.2)
            try:
                conn, addr = sock.accept()
                src_ip = addr[0]
                conn.close()

                now = time.time()
                step, last_seen = client_state.get(src_ip, (0, 0))

                if now - last_seen > timeout:
                    step = 0

                if port == knock_ports[step]:
                    step += 1
                    if step == len(knock_ports):
                        log.info("Valid knock sequence from %s", src_ip)
                        allow_ssh(protected_port, src_ip)
                        step = 0
                else:
                    step = 0

                client_state[src_ip] = (step, now)

            except socket.timeout:
                pass

        gate.settimeout(0.2)
        try:
            client, addr = gate.accept()
            src_ip = addr[0]
            log.info("Proxying SSH session for %s", src_ip)

            backend = socket.create_connection(("172.20.0.20", 2222))
            threading.Thread(target=forward_traffic, args=(client, backend), daemon=True).start()

        except socket.timeout:
            pass


def parse_arguments():
    parser = argparse.ArgumentParser(description="Custom Port Knocking Server")
    parser.add_argument(
        "--sequence",
        default=",".join(str(x) for x in DEFAULT_SEQUENCE)
    )
    parser.add_argument(
        "--protected-port",
        type=int,
        default=DEFAULT_PORT
    )
    parser.add_argument(
        "--window",
        type=float,
        default=DEFAULT_WINDOW
    )
    return parser.parse_args()


def main():
    args = parse_arguments()
    configure_logging()

    try:
        ports = [int(x) for x in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid knock sequence format")

    run_knock_server(ports, args.window, args.protected_port)


if __name__ == "__main__":
    main()
