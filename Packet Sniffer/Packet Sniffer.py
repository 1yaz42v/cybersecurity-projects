import random
import time
from collections import Counter

# Simulated network data
IP_POOL = [f"192.168.1.{i}" for i in range(1, 21)]
DOMAINS = ["google.com", "example.com", "github.com", "wikipedia.org"]
HTTP_PATHS = ["/", "/login", "/api/data", "/home", "/search"]

# Counters to track traffic
protocol_counter = Counter()
top_src_ips = Counter()
top_dst_ips = Counter()
top_domains = Counter()

def generate_packet():
    """Simulate a network packet"""
    protocol = random.choice(["TCP", "UDP", "DNS", "HTTP"])
    src_ip = random.choice(IP_POOL)
    dst_ip = random.choice(IP_POOL)
    packet = {"protocol": protocol, "src_ip": src_ip, "dst_ip": dst_ip}

    if protocol == "DNS":
        packet["domain"] = random.choice(DOMAINS)
    elif protocol == "HTTP":
        packet["host"] = random.choice(DOMAINS)
        packet["path"] = random.choice(HTTP_PATHS)

    return packet

def show_packet(packet):
    """Display packet and update counters"""
    proto = packet["protocol"]
    src = packet["src_ip"]
    dst = packet["dst_ip"]

    if proto in ["TCP", "UDP"]:
        print(f"{proto} {src} -> {dst}")
    elif proto == "DNS":
        print(f"DNS query {src} -> {packet['domain']}")
    elif proto == "HTTP":
        print(f"HTTP request {src} -> {packet['host']}{packet['path']}")

    protocol_counter[proto] += 1
    top_src_ips[src] += 1
    top_dst_ips[dst] += 1
    if proto in ["DNS", "HTTP"]:
        domain = packet.get("domain", packet.get("host", ""))
        top_domains[domain] += 1

def show_summary():
    """Print a quick traffic summary"""
    print("\nTraffic summary:")
    print("Protocols:", dict(protocol_counter))
    print("Top source IPs:", dict(top_src_ips.most_common(5)))
    print("Top destination IPs:", dict(top_dst_ips.most_common(5)))
    print("Top domains:", dict(top_domains.most_common(5)))
    print()

def main():
    print("Fake Packet Sniffer running... Press Ctrl+C to stop.")

    try:
        while True:
            packet = generate_packet()
            show_packet(packet)

            # Every 10 packets, show summary
            if sum(protocol_counter.values()) % 10 == 0:
                show_summary()

            time.sleep(0.5)  # simulate packet arrival
    except KeyboardInterrupt:
        print("\nStopped by user.")
        show_summary()
        print("Bye!")

if __name__ == "__main__":
    main()
