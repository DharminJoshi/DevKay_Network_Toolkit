# DevKay Network Toolkit

![Python](https://img.shields.io/badge/Python-3.7+-blue) [![CC BY-NC 4.0](https://i.creativecommons.org/l/by-nc/4.0/88x31.png)](https://creativecommons.org/licenses/by-nc/4.0/)

**DevKay Network Toolkit** is a comprehensive, terminal-based network utility suite designed for ethical hackers, network administrators, cybersecurity learners, and power users. This Python-powered toolkit consolidates a wide array of network operations — from local LAN scanning to external IP tracking, WHOIS lookups, DNS and SSL inspections, port scans, traceroutes, and live network monitoring — into a single intuitive interface.

---

## 🔑 Key Features

1. **Local Network Scanner**  
   - Scans your LAN for active devices via ARP.  
   - Retrieves IP, MAC address, vendor (via MAC Vendors API), hostname, and online status.

2. **External IP & Domain Tracker**  
   - Resolves domains to IPs or accepts direct IP input.  
   - Fetches geolocation, ISP, organization, ASN, timezone, and more from ip-api.com.

3. **WHOIS Lookup**  
   - Gathers domain/IP registration details (owner, registrar, creation/expiry dates).

4. **DNS Records Fetcher**  
   - Retrieves common record types: A, AAAA, MX, NS, and TXT.

5. **SSL Certificate Inspector**  
   - Connects on port 443 and extracts issuer, validity period, and certificate details.

6. **Port Scanner**  
   - Scans a set of common TCP ports (e.g., 21, 22, 80, 443, 3306, 8080).

7. **Nmap Integration**  
   - Executes `nmap -A -T4` scan if `nmap` is installed.
    >Note: Nmap must be installed on your system and available in PATH for this feature to work.

8. **Traceroute**  
   - Runs system `tracert` (Windows) or falls back appropriately to visualize hop-by-hop path.

9. **Live Network Monitor**  
   - Periodically re-scans the LAN and alerts on device join/leave events.

10. **Subnet Scanner**  
    - Pings all hosts in a given IPv4 subnet (e.g., `192.168.1.0/24`).

11. **HTTP Header Fetcher**  
    - Performs an HTTP HEAD request to display response headers.

12. **MAC Vendor Lookup**  
    - Resolves a MAC address to its manufacturer via macvendors.com API.

---

## 🛠️ Technologies & Dependencies

- **Language:** Python 3.7+
- **Modules:**
  - `socket` — raw network sockets
  - `requests` — HTTP requests
  - `dnspython` — DNS querying
  - `python-whois` — WHOIS data
  - `ssl` — TLS connections
  - `hashlib` — hashing for live monitoring
  - `ipaddress` — subnet parsing
  - plus standard libraries: `subprocess`, `threading`, `time`, `re`, `os`, `sys`, `webbrowser`.

---

## 🚀 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/DharminJoshi/DevKay_Network_Toolkit.git
   ```
2. **Change into directory**
   ```bash
   cd DevKay_Network_Toolkit
   ```
3. **Create & activate a virtual environment (optional but recommended)**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```
4. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

---

## ▶️ Usage

Run the main script:
```bash
python devkay_network_toolkit.py
```
Follow the interactive menu prompts to select from the available tools:

1. **Scan Local Network**  
2. **Track External IP or Domain**  
3. **Display Local Device IP**  
4. **Run Nmap Scan**  
5. **Live Local Network Monitor**  
6. **Traceroute to Target**  
7. **Scan Subnet**  
8. **Fetch HTTP Headers**  
9. **Exit**

Each option provides guided input prompts and displays detailed output in the terminal.

---

## 📂 Project Structure

```text
DevKay_Network_Toolkit/
├── devkay_network_toolkit.py # Main executable script
├── requirements.txt          # Python dependencies
├── LICENSE                   # MIT license file
├── README.md                 # Project documentation

```

---

## 🤝 Contributing

Contributions are welcome! To suggest improvements or report issues:

1. Fork the repo.  
2. Create a new branch: `git checkout -b feature/awesome-feature`.  
3. Commit your changes: `git commit -m "Add awesome feature"`.  
4. Push to your branch: `git push origin feature/awesome-feature`.  
5. Open a Pull Request.

Please adhere to the existing code style and include tests or screenshots where applicable.

## 💼 License

This project is licensed under the **Creative Commons Attribution-NonCommercial 4.0 International License (CC BY-NC 4.0)**. You are free to share, adapt, and modify the project for non-commercial purposes, provided that you give appropriate credit to the original creator (Dharmin Joshi/DevKay). Commercial use of this project is not permitted.

For more details, see the full license: [Creative Commons Attribution-NonCommercial 4.0 International License](https://creativecommons.org/licenses/by-nc/4.0/).

---

## © Copyright Disclaimer:

This project, **DevKay_Network_Toolkit**, is intended for educational and personal use only. All content, including code, images, and resources, are used under the principle of fair use. The project is a non-commercial, open-source endeavor created for learning purposes and is not associated with any official or commercial entity.

All trademarks, logos, and brand names mentioned or used in this project are the property of their respective owners. This project does not claim ownership of any of these trademarks, logos, or brand names.

The project is provided "as is" without any warranties, express or implied. The creator of this project is not responsible for any direct or indirect consequences arising from its use.

This project belongs to **DharminJoshi/DevKay** and is hosted on GitHub.

---

## ⚠️ Disclaimer

This toolkit, **DevKay_Network_Toolkit**, is developed strictly for **educational purposes**, **ethical hacking**, and **authorized network testing** only.

By using this toolkit, you agree to the following:

- You will only scan, probe, or interact with **networks and systems you own** or have received **explicit written permission** to test.
- You understand that **unauthorized access**, **reconnaissance**, or **penetration testing** of networks or devices without permission may **violate local, national, or international laws**, and may lead to **civil or criminal penalties**.
- You assume **full responsibility** for any actions performed using this toolkit.
- The developer (**Dharmin Joshi / DevKay**) shall not be held liable for **any misuse**, **data loss**, **damage**, or **legal consequences** arising from improper or unauthorized use of this tool.

> Always practice **responsible disclosure**, respect **privacy laws**, and follow the **legal and ethical guidelines** of cybersecurity.

If you're unsure whether your usage is permitted, consult with your network administrator, legal advisor, or governing body **before proceeding**.

---

## 📬 Contact

For any queries, suggestions, or feedback, feel free to reach out:

- **Developer:** Dharmin Joshi / DevKay
- **Email:** info.dharmin@gmail.com
- **LinkedIn:** [https://www.linkedin.com/in/dharmin-joshi-3bab42232/](https://www.linkedin.com/in/dharmin-joshi-3bab42232/)
- **GitHub:** [https://github.com/DharminJoshi](https://github.com/DharminJoshi)

---

Thank you for using **Devkay_Network_Toolkit**!

---
