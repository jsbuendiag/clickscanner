#!/usr/bin/env python3
import asyncio
import argparse
import sys
import httpx
import re
import os
from typing import List, Optional, Tuple
from datetime import datetime
from urllib.parse import urlparse

# --- Constants and Config ---
HEADER_THICK_LINE = "-" * 50
HEADER_THIN_LINE = "-" * 30

def generate_poc(url: str):
    """
    Generates a Clickjacking Proof of Concept HTML file for a vulnerable URL.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(script_dir, "clickjacking_PoC.html")
    
    try:
        with open(template_path, "r", encoding="utf-8") as f:
            template_content = f.read()
            
        # Replace the hardcoded target URL with the vulnerable URL
        poc_content = re.sub(r'const targetUrl = ".*?";', f'const targetUrl = "{url}";', template_content)
        
        # Create a safe filename based on the URL
        parsed = urlparse(url)
        safe_name = parsed.netloc.replace(":", "_") if parsed.netloc else "vulnerable_target"
        filename = os.path.join(script_dir, f"poc_{safe_name}.html")
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(poc_content)
            
        print(f"[+] Automatically generated PoC: {filename}")
    except Exception as e:
        print(f"[-] Failed to generate PoC for {url}: {e}")

# --- Scanner Core ---

def format_url(target: str, port: int) -> str:
    """
    Constructs a valid URL with the specified port.
    """
    # Remove existing protocol and port if present for clean construction
    clean_target = re.sub(r'^https?://', '', target)
    clean_target = re.sub(r':\d+$', '', clean_target)
    
    # Heuristic: use https for 443, http for others (can be improved)
    protocol = "https" if port == 443 else "http"
    return f"{protocol}://{clean_target}:{port}"

async def check_target(client: httpx.AsyncClient, target: str, port: int) -> str:
    """
    Scans a single target on a specific port and returns a formatted result string.
    """
    url = format_url(target, port)

    try:
        response = await client.get(url)
        headers = response.headers

        # Check CSP frame-ancestors
        csp = headers.get("Content-Security-Policy", "")
        if "frame-ancestors" in csp:
            return f"[SAFE] {url} - Protected by Content-Security-Policy: frame-ancestors"

        # Check X-Frame-Options
        xfo = headers.get("X-Frame-Options", "").upper()
        if xfo in ("DENY", "SAMEORIGIN", "ALLOW-FROM"):
            return f"[SAFE] {url} - Protected by X-Frame-Options: {xfo}"

        # If none of the above matches
        return f"[VULNERABLE] {url}"

    except httpx.ConnectError:
        return f"[SKIP] {url} - Port closed or unreachable"
    except httpx.TimeoutException:
        return f"[ERROR] {url} - Request timed out"
    except httpx.RequestError as exc:
        return f"[ERROR] {url} - Connection failed: {exc}"
    except Exception as exc:
        return f"[ERROR] {url} - Unexpected error: {exc}"

async def run_scanner(targets: List[str], ports: List[int], output_file: str, timeout: int):
    """
    Orchestrates the scanning process for multiple targets and ports.
    """
    print(HEADER_THICK_LINE)
    print("Clickjacking Detection Report")
    print(f"Targets: {len(targets)} | Ports: {', '.join(map(str, ports))}")
    print(HEADER_THICK_LINE)

    results = []
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        # Create tasks for all target/port combinations
        tasks = []
        for target in targets:
            for port in ports:
                tasks.append(check_target(client, target, port))
        
        # Execute and report real-time
        for future in asyncio.as_completed(tasks):
            result = await future
            print(result)
            results.append(result)
            
            if result.startswith("[VULNERABLE]"):
                try:
                    url = result.split(" ", 1)[1].strip()
                    generate_poc(url)
                except IndexError:
                    pass

    # Summary and Data Saving
    print(HEADER_THICK_LINE)
    num_checked = len(results)
    num_vulnerable = sum(1 for r in results if r.startswith("[VULNERABLE]"))
    num_skipped = sum(1 for r in results if r.startswith("[SKIP]"))
    num_errors = sum(1 for r in results if r.startswith("[ERROR]"))
    
    summary = f"Scan complete. {num_checked} probes. {num_vulnerable} vulnerable, {num_skipped} skipped, {num_errors} errors."
    print(summary)
    print(f"Results saved to {output_file}")

    # Write to file
    with open(output_file, "w") as f:
        f.write(HEADER_THICK_LINE + "\n")
        f.write("Clickjacking Detection Report\n")
        f.write(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Discovery: Targets={len(targets)}, Ports={ports}\n")
        f.write(HEADER_THICK_LINE + "\n\n")
        for res in results:
            f.write(res + "\n")
        f.write("\n" + HEADER_THICK_LINE + "\n")
        f.write(summary + "\n")

# --- Interface ---

def main():
    parser = argparse.ArgumentParser(description="Security Tool: Clickjacking Vulnerability Scanner with Port Discovery")
    parser.add_argument("-u", "--url", help="Scan a single target URL or domain")
    parser.add_argument("-w", "--wordlist", help="Path to a bulk wordlist file of targets")
    parser.add_argument("-p", "--ports", default="80,443", help="Comma-separated list of ports to scan (default: 80,443)")
    parser.add_argument("-o", "--output", default="results.txt", help="Output file for results (default: results.txt)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Timeout in seconds for HTTP requests (default: 10)")

    args = parser.parse_args()

    # Parse ports
    try:
        ports = [int(p.strip()) for p in args.ports.split(",")]
    except ValueError:
        print(f"Error: Invalid port list: {args.ports}")
        sys.exit(1)

    targets = []
    if args.url:
        targets.append(args.url)
    
    if args.wordlist:
        try:
            with open(args.wordlist, "r") as f:
                targets.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"Error: Wordlist file not found: {args.wordlist}")
            sys.exit(1)

    if not targets:
        print("Error: No targets provided. Use -u or -w.")
        parser.print_help()
        sys.exit(1)

    # Run the async scanner
    asyncio.run(run_scanner(targets, ports, args.output, args.timeout))

if __name__ == "__main__":
    main()
