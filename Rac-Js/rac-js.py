import argparse
import re
import requests
import time
import os
from concurrent.futures import ThreadPoolExecutor

# ANSI Color Codes for terminal beautification
class Colors:
    GREEN = '\033[92m'
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class EndpointScanner:
    def __init__(self, output_path=None, silent=False):
        self.output_path = output_path
        self.is_silent = silent
        self.found_count = 0
        self.seen_endpoints = set()
        self.ua_header = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        }
        self.patterns = self._load_patterns("./regex.tmp")

    def _load_patterns(self, file_path):
        compiled = []
        if not os.path.exists(file_path):
            print(f"{Colors.YELLOW}[!] Configuration missing: {file_path}{Colors.RESET}")
            return []
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    pattern = line.strip()
                    if pattern:
                        compiled.append(re.compile(pattern))
            return compiled
        except Exception:
            return []

    def _is_clean(self, text):
        blacklist = {'"/$"', '"/*"', '"?"', '"/"', '"//"', '`/`', "==="}
        forbidden = set(":;,()|[]!<>^*+ ")
        if text in blacklist or "===" in text:
            return False
        return not any(char in forbidden for char in text)

    def _log_result(self, source_url, match):
        """Beautified output with terminal coloring and clean spacing."""
        if match not in self.seen_endpoints:
            self.seen_endpoints.add(match)
            self.found_count += 1
            
            # Formatting for console (with colors)
            console_msg = (
                f"{Colors.GREEN}[+]{Colors.RESET} {Colors.BOLD}Found URI:{Colors.RESET} "
                f"{Colors.CYAN}{match:<25}{Colors.RESET} "
                f"{Colors.BLUE}Origin:{Colors.RESET} {source_url}"
            )
            
            # Clean text for file (no colors)
            file_msg = f"[+] Found : {match} "
            
            if not self.is_silent:
                print(console_msg)
            
            if self.output_path:
                try:
                    with open(self.output_path, 'a') as f:
                        f.write(file_msg + "\n")
                except Exception:
                    pass

    def process_target(self, url):
        url = url.strip()
        if not url: return
        if not url.startswith("http"):
            url = "http://" + url
            
        try:
            # Setting a reasonable timeout for scanning
            resp = requests.get(url, headers=self.ua_header, timeout=8, verify=False)
            if resp.status_code == 200:
                source_code = resp.text
                for p in self.patterns:
                    matches = p.findall(source_code)
                    for m in matches:
                        target = m[0] if isinstance(m, tuple) else m
                        if self._is_clean(target):
                            self._log_result(url, target)
        except Exception:
            pass

def main():
    # Hide InsecureRequestWarnings if scanning https with verify=False
    print(rf"""
 /$$$$$$$   /$$$$$$   /$$$$$$           /$$$$$  /$$$$$$ 
| $$__  $$ /$$__  $$ /$$__  $$         |__  $$ /$$__  $$
| $$  \ $$| $$  \ $$| $$  \__/            | $$| $$  \__/
| $$$$$$$/| $$$$$$$$| $$                  | $$|  $$$$$$ 
| $$__  $$| $$__  $$| $$             /$$  | $$ \____  $$
| $$  \ $$| $$  | $$| $$    $$      | $$  | $$ /$$  \ $$
| $$  | $$| $$  | $$|  $$$$$$/      |  $$$$$$/|  $$$$$$/
|__/  |__/|__/  |__/ \______/        \______/  \______/ 
                                                        
                                                        
                                                        

                                                                                                   
    """)
    requests.packages.urllib3.disable_warnings()
    
    parser = argparse.ArgumentParser(description="Advanced URI Discovery")
    parser.add_argument("-file", help="Input URL list")
    parser.add_argument("-url", help="Single target")
    parser.add_argument("-out", help="Save discovered data")
    parser.add_argument("-quiet", action="store_true")
    
    args = parser.parse_args()
    
    if not args.file and not args.url:
        print(f"{Colors.YELLOW}Usage: python tool.py -url <target> or -file <list.txt>{Colors.RESET}")
        return

    # Banner for a more professional look
    if not args.quiet:
        print(f"{Colors.BOLD}{Colors.BLUE}--- Fnding Secrets.... ---{Colors.RESET}\n")

    scanner = EndpointScanner(output_path=args.out, silent=args.quiet)
    start_mark = time.time()

    with ThreadPoolExecutor(max_workers=15) as executor:
        if args.url:
            executor.submit(scanner.process_target, args.url)
        
        if args.file and os.path.exists(args.file):
            with open(args.file, 'r') as f:
                targets = f.readlines()
                executor.map(scanner.process_target, targets)

    # Mimicking the original delay logic
    time.sleep(7)
    duration = (time.time() - start_mark - 7)
    
    if not args.quiet:
        print(f"\n{Colors.GREEN}[*] Analysis complete.{Colors.RESET}")
        print(f"{Colors.BOLD}Duration:{Colors.RESET} {duration:.2f}s | {Colors.BOLD}Unique Entries:{Colors.RESET} {scanner.found_count}")

if __name__ == "__main__":
    main()
