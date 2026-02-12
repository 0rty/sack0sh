<div align="center">

<pre>
  _________              __   _______         .__     
 /   _____/____    ____ |  | _\   _  \   _____|  |__  
 \_____  \\__  \ _/ ___\|  |/ /  /_\  \ /  ___/  |  \ 
 /        \/ __ \\  \___|    <\  \_/   \\___ \|   Y  \
/_______  (____  /\___  >__|_ \\_____  /____  >___|  /
        \/     \/     \/     \/      \/     \/     \/ 
</pre>

</div>

---

## 📌 Overview

**Sack0sh** is a Linux-based penetration testing tool designed to demonstrate and exploit common network vulnerabilities.

It allows security students and professionals to simulate:

- CAM Table Flooding
- CAM Spoofing
- ARP Spoofing
- DHCP Starvation

The tool operates using raw sockets and requires **root privileges**.


---

## Features

- Random realistic MAC address generation (vendor-based OUI simulation)
- Raw Ethernet frame crafting
- Multiple verbosity levels
- Modular attack architecture
- Lightweight and dependency-free (standard Python libraries)

---

## Requirements

- Linux OS
- Python 3.x
- Root privileges
- Network interface in active mode

---

## Installation

```bash
git clone https://github.com/0rty/Sack0sh.git
cd Sack0sh
chmod +x sack0sh.py
```

---

## ⚠️ Disclaimer

This tool is developed **for educational and authorized security testing purposes only**.

You must:

- Use it only on networks you own
- Or have explicit written authorization to test

The author assumes **no responsibility** for misuse or illegal activities.





