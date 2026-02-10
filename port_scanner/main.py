#!/usr/bin/env python3
"""
Port Scanner - Starter Template for Students
Assignment 2: Network Security

This is a STARTER TEMPLATE to help you get started.
You should expand and improve upon this basic implementation.

TODO for students:
1. Implement multi-threading for faster scans
2. Add banner grabbing to detect services
3. Add support for CIDR notation (e.g., 192.168.1.0/24)
4. Add different scan types (SYN scan, UDP scan, etc.)
5. Add output formatting (JSON, CSV, etc.)
6. Implement timeout and error handling
7. Add progress indicators
8. Add service fingerprinting
"""

import socket
import sys


def scan_port(target, port, timeout=1.0):
    """
    Scan a single port on the target host

    Args:
        target (str): IP address or hostname to scan
        port (int): Port number to scan
        timeout (float): Connection timeout in seconds

    Returns:
        bool: True if port is open, False otherwise
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))

        banner = ""
        try:
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode(errors="ignore").strip()
        except:
            pass

        if banner:
            print(f"[OPEN] Port {port} | Banner: {banner.splitlines()[0]}")
        else:
            print(f"[OPEN] Port {port}")

        s.close()
        return True

    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def scan_range(target, start_port, end_port):
    """
    Scan a range of ports on the target host

    Args:
        target (str): IP address or hostname to scan
        start_port (int): Starting port number
        end_port (int): Ending port number

    Returns:
        list: List of open ports
    """
    open_ports = []

    print(f"[*] Scanning {target} from port {start_port} to {end_port}")
    print(f"[*] This may take a while...")

    # TODO: Implement the scanning logic
    # Hint: Loop through port range and call scan_port()
    # Hint: Consider using threading for better performance

    for port in range(start_port, end_port + 1):
        is_open = scan_port(target, port)
        if is_open:
            open_ports.append(port)

    return open_ports


def main():
    """Main function"""
    # TODO: Parse command-line arguments
    # TODO: Validate inputs
    # TODO: Call scan_range()
    # TODO: Display results

    # Example usage (you should improve this):
    if len(sys.argv) < 2:
        print("Usage: python3 port_scanner_template.py <target>")
        print("Example: python3 port_scanner_template.py 172.20.0.10")
        sys.exit(1)

    target = sys.argv[1]
    start_port = 1
    end_port = 10000  # Scan first 1024 ports by default

    print(f"[*] Starting port scan on {target}")

    open_ports = scan_range(target, start_port, end_port)

    print(f"\n[+] Scan complete!")
    print(f"[+] Found {len(open_ports)} open ports:")
    for port in open_ports:
        print(f"    Port {port}: open")


if __name__ == "__main__":
    main()
