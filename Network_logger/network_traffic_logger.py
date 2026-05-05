from scapy.all import sniff, IP, TCP, UDP
import time
import json


FLOW_TABLE = {} # Curent network activity
NETWORK_STATS = {} # Total network activity
FLOW_TIMEOUT = 30


def get_flow_key(packet):
    if not packet.haslayer(IP):
        return None
    
    ip = packet[IP]
    protocol = ip.proto
    sport = dport = 0

    if packet.haslayer(TCP):
        sport = packet[TCP].sport
        dport = packet[TCP].dport

    elif packet.haslayer(UDP):
        sport = packet[UDP].sport
        dport = packet[UDP].dport

    return (ip.src, ip.dst, sport, dport, protocol)


# Ensure (A -> B) == (B -> A)
def normalize_flow_key(flow_key):
    src_ip, dest_ip, sport, dport, protocol = flow_key


    if src_ip < dest_ip:
        return (src_ip, dest_ip, sport, dport, protocol)
    else:
        return (dest_ip, src_ip, dport, sport, protocol)


def is_flow_expired(flow):
    now = time.time()
    return (now - flow["last_seen"]) > FLOW_TIMEOUT


def expire_flows():
    expired = []

    for key in list(FLOW_TABLE.keys()):
        flow = FLOW_TABLE[key]
        if is_flow_expired(flow):
            print(f"EXPIRED FLOW: {key}")
            print(f"\tpackets: {flow['packets']}")
            print(f"\tbytes: {flow['bytes']}")
            print(f"\tduration: {(flow['last_seen'] - flow['first_seen']):.2f} s")
            print()
            expired.append(key)

    for key in expired:
        del FLOW_TABLE[key]


def update_network_stats(key, packet_len):
    src = key[0]
    dest = key[1]

    if src not in NETWORK_STATS:
        NETWORK_STATS[src] = {"bytes": 0, "packets": 0}
    
    if dest not in NETWORK_STATS:
        NETWORK_STATS[dest] = {"bytes": 0, "packets": 0}

    NETWORK_STATS[src]["bytes"] += packet_len
    NETWORK_STATS[src]["packets"] += 1

    NETWORK_STATS[dest]["bytes"] += packet_len
    NETWORK_STATS[dest]["packets"] += 1


def handle_packet(packet):
    global NETWORK_STATS

    key = get_flow_key(packet)
    if not key:
        return
    key = normalize_flow_key(key)
    
    packet_len = len(bytes(packet))
    now = time.time()

    if key in FLOW_TABLE:
        flow = FLOW_TABLE[key]
        flow["packets"] += 1
        flow["bytes"] += packet_len
        flow["last_seen"] = now

    else:
        FLOW_TABLE[key] = {
            "packets" : 1,
            "bytes" : packet_len,
            "first_seen" : now,
            "last_seen" : now
        }

    update_network_stats(key, packet_len)


def print_active_flows():
    print("=== ACTIVE NETWORK FLOWS ===")
    for key, flow in list(FLOW_TABLE.items()):
        print(f"{key[0]}:{key[2]} -> {key[1]}:{key[3]} (protocol {key[4]})")
        print(f"\tbytes: {flow['bytes']}")
        print(f"\tpackets: {flow['packets']}")
        print(f"\tlast seen: {flow['last_seen']}")
        print()


def export_to_jsonl(filename = "network_stats.jsonl"):
    snapshot = {
        "timestamp" : time.time(),
        "total_stats" : NETWORK_STATS,
        # convert to ket to string to match json requirements
        "active_flows" : {str(key): flow for key, flow in list(FLOW_TABLE.items())}
    }

    with open(filename, 'a') as f:
        f.write(json.dumps(snapshot) + "\n")


def run_monitor(interface): # Main function
    print(f"Starting network monitor on {interface}...")

    last_print = time.time()
    last_export = time.time()

    def print_and_export():
        nonlocal last_print, last_export

        now = time.time()
        expire_flows()

        if now - last_print >= 5: # print active flows every 5 sec
            print("\033c", end="") # clear terminal
            print_active_flows()
            last_print = now

        if now - last_export >= 30: # export to json every 30 sec
            export_to_jsonl()
            last_export = now
    
    def packet_flow(packet):
        handle_packet(packet)
        print_and_export()

    try:
        sniff(
            iface = interface,
            prn = packet_flow,
            store = False,
            filter = "ip"
        )
    except Exception as e:
        print(f"Error: {e}")



if __name__ == "__main__":
    interface = input("Enter interface (e.g. eth0 or wlan0)")
    run_monitor(interface)