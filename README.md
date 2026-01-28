# Sack0sh

## Overview

This project is a **Python-based laboratory tool** designed for **pentesters, red teamers, and network security students** who want to deepen their understanding of **Layer 2 and Layer 3 network weaknesses**, specifically around **ARP mechanisms** and **switch CAM table behavior**.

The script focuses on **offensive security concepts** in order to better understand:
- how attackers can exploit trust assumptions at lower network layers
- how these attacks impact real network behavior
- how such attacks can be detected and mitigated defensively

This tool is **not intended to be a turnkey exploitation framework**, but rather a **learning and demonstration aid** for security professionals working in authorized environments.

---

## Objectives

The main objectives of this project are to:

- Demonstrate how **ARP operates** at a protocol level
- Highlight why ARP is vulnerable to manipulation and spoofing
- Explain how Ethernet switches populate and rely on **CAM tables**
- Show how CAM table saturation affects traffic forwarding
- Provide practical insight into **Man-in-the-Middle (MITM) prerequisites**
- Bridge theoretical knowledge with **real-world pentesting scenarios**

The project is intentionally scoped to **ARP and CAM-related techniques only**, to maintain a strong focus on lower-layer network fundamentals.

---

## Target Audience

This project is intended for:

- Penetration testers
- Red team operators
- Blue team members seeking to understand attacker techniques
- Network security students and instructors
- Anyone preparing for practical network security assessments

A solid understanding of **TCP/IP networking and OSI layers** is recommended.

---

## Ethical and Legal Warning ⚠️

> **IMPORTANT — READ CAREFULLY**

This tool performs **low-level network operations** that may:
- disrupt network communication
- interfere with switching behavior
- affect other hosts on the same network segment

This script **must only be used**:
- in **authorized penetration tests**
- in **explicitly permitted laboratory environments**
- with the **clear and informed consent of all involved parties**

Unauthorized use of ARP manipulation or CAM flooding techniques:
- may violate laws and regulations
- may breach organizational security policies
- may cause unintended network outages

By using this project, you acknowledge that:
- you have explicit authorization to perform such tests
- you understand the potential impact of these techniques
- you assume full responsibility for how the tool is used

The author assumes **no liability** for misuse.

---

## Educational and Defensive Value

From a defensive standpoint, this project helps illustrate:
- why features like **Dynamic ARP Inspection (DAI)** exist
- the importance of **port security and MAC limiting**
- how network segmentation reduces Layer 2 attack surfaces
- why monitoring ARP traffic is critical in enterprise environments

Understanding these offensive techniques enables **stronger defensive designs**.

---

## Environment Requirements

- Linux-based operating system (recommended)
- Python 3.x
- Isolated or virtualized network environment
- Root or administrative privileges (required for raw packet handling)

---

## Disclaimer

This project is provided **strictly for educational and authorized security testing purposes**.  
It is not designed for use as a malicious tool or for unauthorized network interference.

---

## License

This project is released for educational and research purposes.  
Refer to the LICENSE file for additional information.
