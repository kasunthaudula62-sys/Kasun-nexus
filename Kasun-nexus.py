import argparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import sys
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"
BLUE = "\033[94m"
CYAN = "\033[96m"


def banner():
  print(f"""{BLUE}
    __ __  ____                      ____                        
   / //_/ / __ \\ expeditions ______/ __ \\ ____  _  __         
  / ,<   / /_/ / _ \\/ _ \\/ __/ / /_/ / __ \\| |/_/         
 /_/|_\\ / ____/  __  __ / /___  / ____/ /_/ />  <           
       /_/    \\___/\\___/_/     /_/    \\____/_/|_|           
   [ Kasun-Recon-Nexus: Elite CTF & Bug Bounty Suite ]
  {RESET}""")


def check_if_ip(target):
  try:
    ipaddress.ip_address(target)
    return True
  except ValueError:
    return False


def get_targets(target_input):
  targets = set()
  if check_if_ip(target_input):
    print(
        f"{YELLOW}[*] Target is an IP address. Multi-port scanning enabled..."
        f" {RESET}"
    )
    # Common CTF / Web Ports
    ports = [80, 443, 8080, 8443, 3000, 5000]
    for p in ports:
      targets.add(f"{target_input}:{p}")
  else:
    print(
        f"{YELLOW}[*] Fetching subdomains for {target_input} from"
        f" crt.sh...{RESET}"
    )
    targets.add(target_input)
    targets.add(f"www.{target_input}")
    url = f"https://crt.sh/?q=%.{target_input}&output=json"
    try:
      response = requests.get(url, timeout=10)
      if response.status_code == 200:
        data = response.json()
        for entry in data:
          name_value = entry["name_value"]
          for sub in name_value.split("\n"):
            sub = sub.strip().lower()
            if "*" not in sub and sub.endswith(target_input):
              targets.add(sub)
    except Exception as e:
      print(f"{RED}[-] Connection Error on crt.sh: {e}{RESET}")
  return list(targets)


def scan_target(target, report_f):
  urls_to_test = []
  if ":" in target:  # IP with port
    urls_to_test = [f"http://{target}", f"https://{target}"]
  else:
    urls_to_test = [f"https://{target}", f"http://{target}"]

  for target_url in urls_to_test:
    try:
      headers_UA = {
          "User-Agent": (
              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) KasunSecurityScanner/2.6"
          )
      }
      response = requests.get(
          target_url,
          headers=headers_UA,
          timeout=4,
          allow_redirects=True,
          verify=False,
      )
      status = response.status_code
      headers = response.headers
      body = response.text

      print(
          f"\n{GREEN}[+] TARGET ALIVE:{RESET} {target_url}"
          f" {YELLOW}[Status: {status}]{RESET}"
      )
      report_f.write(f"\n[+] TARGET ALIVE: {target_url} [Status: {status}]\n")

      found_issues = []

      # Security Headers
      if "X-Frame-Options" not in headers:
        found_issues.append(
            "[Low] Missing X-Frame-Options Header (Clickjacking Vector)"
        )
      if "Content-Security-Policy" not in headers:
        found_issues.append(
            "[Medium] Missing Content-Security-Policy (CSP) (XSS Weakness)"
        )
      if "X-Content-Type-Options" not in headers:
        found_issues.append("[Low] Missing X-Content-Type-Options Header")

      # Advanced CTF & Bug Bounty Fuzzing Paths
      advanced_paths = [
          "/.git/HEAD",
          "/.env",
          "/phpinfo.php",
          "/robots.txt",
          "/flag.txt",
          "/secret",
          "/admin",
          "/login",
          "/dashboard",
          "/backup.zip",
          "/config.php",
          "/api/v1/",
          "/server-status",
      ]

      print(
          f"{CYAN}[*] Running Advanced Payload & Sensitive File Fuzzing..."
          f" {RESET}"
      )
      for path in advanced_paths:
        test_url = target_url.rstrip("/") + path
        try:
          res = requests.get(
              test_url, headers=headers_UA, timeout=3, verify=False
          )
          if res.status_code == 200:
            if path == "/flag.txt" or "flag{" in res.text.lower():
              found_issues.append(
                  f"[CRITICAL - CTF FLAG] Flag or Flag File Discovered!"
                  f" ({test_url})"
              )
            elif path == "/.git/HEAD" and "ref:" in res.text:
              found_issues.append(
                  f"[CRITICAL] Exposed Git Source Repository Found! ({test_url})"
              )
            elif path == "/.env" and (
                "DB_" in res.text or "API_KEY" in res.text
            ):
              found_issues.append(
                  f"[CRITICAL] Exposed Sensitive .env File! ({test_url})"
              )
            else:
              found_issues.append(
                  f"[High] Active Endpoint Discovered (200 OK): {test_url}"
              )
          elif res.status_code == 403:
            found_issues.append(
                f"[Medium] Forbidden/Protected Endpoint Found (403):"
                f" {test_url}"
            )
        except:
          pass

      # Form Input Detection (Potential XSS / SQLi Entrypoints)
      if "<form" in body.lower():
        found_issues.append(
            "[Info] Input Forms detected on page. Excellent vector for"
            " XSS/SQLi testing."
        )

      # Server Disclosure
      server_banner = headers.get("Server")
      if server_banner:
        found_issues.append(
            f"[Info] Backend Technology Disclosure: {server_banner}"
        )

      if not found_issues:
        found_issues.append(
            "[Info] Target active. Ready for manual Burp Suite interception."
        )

      for issue in found_issues:
        if "CRITICAL" in issue:
          print(f"    {RED} ➔ {issue}{RESET}")
        elif "High" in issue or "Medium" in issue:
          print(f"    {YELLOW} ➔ {issue}{RESET}")
        else:
          print(f"    {CYAN} ➔ {issue}{RESET}")
        report_f.write(f"    ➔ {issue}\n")

      break
    except requests.RequestException:
      continue


if __name__ == "__main__":
  parser = argparse.ArgumentParser(
      description=(
          "Kasun-Recon-Nexus: Ultimate CTF and Bug Bounty Automation Suite"
      )
  )
  parser.add_argument(
      "-t",
      "--target",
      required=True,
      help="Specify target domain or IP (e.g., 10.48.150.169 or target.com)",
  )
  parser.add_argument(
      "-o",
      "--output",
      default="kasun_nexus_report.txt",
      help="Specify report output file",
  )
  args = parser.parse_args()

  banner()
  target_input = args.target
  output_filename = args.output

  targets = get_targets(target_input)
  print(f"{GREEN}[+] Generated {len(targets)} endpoints to scan.{RESET}\n")

  with open(output_filename, "w") as report_file:
    report_file.write(
        "====================================================\n"
    )
    report_file.write("       KASUN-RECON-NEXUS SCAN REPORT                \n")
    report_file.write(
        "====================================================\n"
    )
    report_file.write(f"Target Input: {target_input}\n\n")

    # Multi-threading for high performance execution
    with ThreadPoolExecutor(max_workers=5) as executor:
      executor.map(lambda t: scan_target(t, report_file), targets[:30])

    report_file.write(
        "\n====================================================\n"
    )
    report_file.write("       SCAN COMPLETED SUCCESSFULLY                  \n")
    report_file.write(
        "====================================================\n"
    )

  print(
      f"\n{BLUE}[+] Scan finished successfully! Report saved to:"
      f" {output_filename}{RESET}"
  )
