# Kasun-Recon-Nexus 🛡️🚀

> **Kasun-Recon-Nexus** is an advanced, automated reconnaissance and vulnerability scanning tool built specifically for CTF (Capture The Flag) challenges and Bug Bounty hunting.

---

## 👨‍💻 Created By
* **Name:** Kasun
* **GitHub:** [@kasunthaudula62-sys](https://github.com/kasunthaudula62-sys)

---

## 🔥 Key Features
* **Dual Target Support:** Automatically detects domains or direct IP/Lab addresses.
* **Subdomain Enumeration:** Fetches subdomains via `crt.sh`.
* **Multi-Port Web Scanning:** Scans common web ports (80, 443, 8080, 8443, etc.).
* **Sensitive File & Path Fuzzing:** Detects `.git`, `.env`, `robots.txt`, and CTF `flag.txt`.
* **Security Headers Analysis:** Checks for missing headers like `X-Frame-Options` and `CSP`.
* **Multi-Threading:** High-performance concurrent scanning.

---

## ⚙️ Installation & Usage (Kali Linux)

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/kasunthaudula62-sys/kasun-nexus.git](https://github.com/kasunthaudula62-sys/kasun-nexus.git)
   chmod +x kasun_nexus.py
2.Make it executable:
```bash 
chmod +x kasun_nexus.py
3.Run the tool:
python3 kasun_nexus.py -t <TARGET_IP_OR_DOMAIN> -o report.txt




