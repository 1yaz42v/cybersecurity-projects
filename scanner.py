import socket
import sys
from typing import Tuple
import argparse
from concurrent.futures import ThreadPoolExecutor
import threading

def scan_port(ip: str, port: int) -> bool:
    """Scan a single port on the target IP and return whether it's open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.3)  # Reduced for faster scans
            result = sock.connect_ex((ip, port))
            if result == 0:
                with threading.Lock():  # Ensure thread-safe printing
                    print(f"[+] Port {port} is OPEN")
                return True
            return False
    except socket.gaierror:
        print(f"[-] Error: Could not resolve hostname {ip}")
        return False
    except socket.error as e:
        with threading.Lock():
            print(f"[-] Error scanning port {port}: {e}")
        return False

def scan_ports(ip: str, start_port: int, end_port: int, max_threads: int = 50) -> None:
    """Scan a range of ports on the target IP using multithreading."""
    print(f"\nStarting port scan on {ip} (ports {start_port} to {end_port})...\n")
    
    open_ports = []
    ports = range(start_port, end_port + 1)
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        # Map scan_port to all ports, passing the IP
        results = executor.map(lambda p: scan_port(ip, p), ports)
        open_ports = [port for port, is_open in zip(ports, results) if is_open]
    
    print("\nScan complete!")
    if open_ports:
        print(f"Open ports found: {', '.join(map(str, open_ports))}")
    else:
        print("No open ports found in the specified range.")

def parse_arguments() -> Tuple[str, int, int]:
    """Parse command-line arguments for port range and optional IP."""
    parser = argparse.ArgumentParser(
        description="Fast TCP port scanner with threading",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "-i", "--ip",
        help="Target IP address or hostname to scan (if not provided, will prompt)",
        default=None
    )
    parser.add_argument(
        "-s", "--start-port",
        type=int,
        default=1,
        help="Starting port number"
    )
    parser.add_argument(
        "-e", "--end-port",
        type=int,
        default=1024,
        help="Ending port number"
    )
    
    args = parser.parse_args()
    
    # Validate port range
    if args.start_port < 1 or args.end_port > 65535:
        parser.error("Ports must be between 1 and 65535")
    if args.start_port > args.end_port:
        parser.error("Start port must be less than or equal to end port")
    
    # Prompt for IP if not provided
    if args.ip is None:
        args.ip = input("Enter the target IP address or hostname to scan: ").strip()
        if not args.ip:
            parser.error("An IP address or hostname is required")
    
    return args.ip, args.start_port, args.end_port

def main():
    """Main function to run the port scanner."""
    try:
        ip, start_port, end_port = parse_arguments()
        scan_ports(ip, start_port, end_port)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()