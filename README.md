# Sack0sh

```
  _________              __   _______         .__     
 /   _____/____    ____ |  | _\   _  \   _____|  |__  
 \_____  \\__  \ _/ ___\|  |/ /  /_\  \ /  ___/  |  \ 
 /        \/ __ \\  \___|    <\  \_/   \\___ \|   Y  \
/_______  (____  /\___  >__|_ \\_____  /____  >___|  /
        \/     \/     \/     \/      \/     \/     \/ 
```

A low-level network pentesting tool written in pure Python 3 using raw sockets — no external dependencies.

> **DISCLAIMER** — This tool is for **educational purposes only**. Always obtain proper authorization before performing any security testing. Never use this tool on networks or systems you do not own or have explicit permission to test.

---

## Features

| Attack | Description |
|--------|-------------|
| `CF` | **CAM Flooding** — Floods the switch CAM table with random MAC addresses |
| `CS` | **CAM Spoofing** — Sends frames with a spoofed source MAC to poison the CAM table |
| `ARPS` | **ARP Spoofing** — Poisons ARP caches to perform a Man-in-the-Middle attack |
| `DHCPSTARV` | **DHCP Starvation** — Exhausts the DHCP pool by sending DISCOVER + REQUEST with random MACs |

---

## Requirements

- Linux (raw sockets require `AF_PACKET`)
- Python 3.10+ (uses `match` statement)
- Root privileges

No external dependencies — uses only the Python standard library (`socket`, `struct`, `threading`, `subprocess`).

---

## Installation

```bash
git clone https://github.com/your-username/sack0sh
cd sack0sh
```

---

## Usage

```bash
sudo python3 sack0sh.py -i <interface> -a <attack> [options]
```

### Arguments

| Argument | Description | Required |
|----------|-------------|----------|
| `-i`, `--interface` | Network interface to use | ✅ Always |
| `-a`, `--attack` | Attack type: `CF`, `CS`, `ARPS`, `DHCPSTARV` | ✅ Always |
| `-t`, `--target` | Target IP address | Depends on attack |
| `-t2`, `--target2` | Second target IP (ARP Spoofing only) | `ARPS` only |
| `-m`, `--mac` | Victim MAC address | `CS` only |
| `-v`, `--verbose` | Verbose output | ❌ |
| `-vv`, `--very-verbose` | Debug output | ❌ |

### Examples

```bash
# CAM Flooding
sudo python3 sack0sh.py -i eth0 -a CF -vv

# CAM Spoofing (requires victim MAC)
sudo python3 sack0sh.py -i eth0 -a CS -m aa:bb:cc:dd:ee:ff

# ARP Spoofing (MITM between victim and gateway)
sudo python3 sack0sh.py -i eth0 -t 192.168.1.10 -t2 192.168.1.1 -a ARPS -v

# DHCP Starvation
sudo python3 sack0sh.py -i eth0 -a DHCPSTARV -vv
```

---

## How It Works

### CAM Flooding (`CF`)

Switches maintain a CAM (Content Addressable Memory) table that maps MAC addresses to ports. This table has a limited size. By flooding the switch with frames using random spoofed MAC addresses, the CAM table overflows and the switch falls back to broadcasting all traffic — behaving like a hub. This allows an attacker to sniff traffic not destined for their machine.

```
Attacker → sends thousands of frames with random MACs
         → CAM table fills up
         → switch broadcasts all traffic to all ports
         → attacker can sniff everything
```

### CAM Spoofing (`CS`)

Sends frames with the attacker's real MAC as source but targeting a specific victim MAC as destination. This poisons the switch's CAM table entry for the victim, redirecting traffic intended for the victim to the attacker's port.

### ARP Spoofing (`ARPS`)

ARP (Address Resolution Protocol) maps IP addresses to MAC addresses on a local network. Since ARP has no authentication, an attacker can send unsolicited ARP replies to poison the ARP cache of two targets — making each believe the attacker's MAC corresponds to the other's IP.

```
Normal:   Victim ←→ Gateway
Poisoned: Victim ←→ Attacker ←→ Gateway  (MITM)
```

The tool automatically:
- Resolves real MACs via ARP requests
- Enables IP forwarding so traffic keeps flowing
- Sends poison packets every 2 seconds
- Restores real ARP tables on Ctrl+C

### DHCP Starvation (`DHCPSTARV`)

Exhausts a DHCP server's IP pool by sending a flood of DHCP DISCOVER messages with random spoofed MAC addresses, then completing the full DISCOVER → OFFER → REQUEST → ACK handshake for each one. Once the pool is full, legitimate clients can no longer obtain an IP address.

```
Attacker → DISCOVER (random MAC)
         ← OFFER (server assigns IP)
Attacker → REQUEST (claims the IP)
         ← ACK (IP locked)
         → repeat until pool is exhausted
```

---

## Test Lab Setup

A minimal isolated lab using VirtualBox with 3 VMs.

### Architecture

<div align="center">

```
 ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
 │    Attacker      │     │     Victim       │     │    Gateway       │
 │   Kali Linux     │     │  Ubuntu Server   │     │  Ubuntu Server   │
 │  192.168.100.10  │     │  192.168.100.20  │     │  192.168.100.1   │
 └────────┬─────────┘     └────────┬─────────┘     └────────┬─────────┘
│                        │                        │
└────────────────────────┴────────────────────────┘
 Internal Network
192.168.100.0/24
```

</div>

### Step 1 — VirtualBox Network

For each VM, set the network adapter to **Internal Network**:
```
VM → Settings → Network → Adapter 1
    → Attached to: Internal Network
    → Name: pentest-lab
```

### Step 2 — Attacker (Kali Linux)

Download the pre-built VirtualBox image from https://www.kali.org/get-kali/#kali-virtual-machines.

Configure a static IP:
```bash
sudo ip addr add 192.168.100.10/24 dev eth0
sudo ip link set eth0 up
```

Clone the tool:
```bash
git clone https://github.com/your-username/sack0sh
```

### Step 3 — Victim (Ubuntu Server 22.04)

Configure a static IP via netplan:
```bash
sudo nano /etc/netplan/00-installer-config.yaml
```
```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      addresses: [192.168.100.20/24]
```
```bash
sudo netplan apply
sudo apt install net-tools -y   # for arp -n
```

### Step 4 — Gateway / DHCP Server (Ubuntu Server 22.04)

Configure a static IP:
```bash
sudo nano /etc/netplan/00-installer-config.yaml
```
```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      addresses: [192.168.100.1/24]
```
```bash
sudo netplan apply
```

Install and configure dnsmasq:
```bash
sudo apt install dnsmasq -y
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
sudo nano /etc/dnsmasq.conf
```
```
port=0
interface=enp0s3
dhcp-range=192.168.100.50,192.168.100.100,12h
```
```bash
sudo systemctl restart dnsmasq
```

### Step 5 — Verify the lab

```bash
# From Kali
ping 192.168.100.1    # gateway reachable?
ping 192.168.100.20   # victim reachable?
```

---

## Testing Each Attack

### CAM Flooding
```bash
# Kali
sudo python3 sack0sh.py -i eth0 -a CF -vv

# Victim — watch broadcast traffic explode
sudo tcpdump -i enp0s3 -e
```

### ARP Spoofing
```bash
# Victim — note the real MAC of the gateway BEFORE the attack
arp -n

# Kali — start the attack
sudo python3 sack0sh.py -i eth0 -t 192.168.100.20 -t2 192.168.100.1 -a ARPS -vv

# Victim — the gateway's MAC should now be the attacker's MAC
watch -n1 arp -n
```

### DHCP Starvation
```bash
# Kali — start the attack
sudo python3 sack0sh.py -i eth0 -a DHCPSTARV -vv

# Gateway — watch the leases fill up
watch -n1 cat /var/lib/misc/dnsmasq.leases

# Victim — try to get an IP once the pool is full (should fail)
sudo dhclient enp0s3
```

---

## License

MIT License — see `LICENSE` for details.
