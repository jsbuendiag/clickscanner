# ClickScanner

A fast, asynchronous Python security scanner to detect Clickjacking vulnerabilities. When vulnerable pages are found, the tool automatically generates HTML Proof of Concept (PoC) files that demonstrate the exploit.

## What it does
The Clickjacking Scanner probes target URLs or a bulk list of domains to determine if they can be maliciously framed. Framing a website inside an iframe is the core mechanism of Clickjacking attacks (UI redressing). The scanner not only detects if the target lacks proper protections but also automatically crafts an HTML Proof of Concept to illustrate the vulnerability.

## How it works
The scanner uses Python's `asyncio` and `httpx` to perform rapid, non-blocking HTTP requests against target domains mapped across multiple ports. For each response, it inspects two critical security headers:
1. **`Content-Security-Policy` (CSP)**: It checks if the `frame-ancestors` directive is present, which restricts which domains can frame the site.
2. **`X-Frame-Options` (XFO)**: It checks if the header is set to `DENY`, `SAMEORIGIN`, or `ALLOW-FROM`.

If neither of these robust protections is found, the target is flagged as `[VULNERABLE]`, and the PoC generation is immediately triggered. The results are printed to the console in real-time and saved to a comprehensive summary report.

## Options and Usage
You can run the script against a single target or a bulk wordlist.

```bash
python3 scanner.py [options]
```

### Options
* `-u`, `--url`: Scan a single target URL or domain (e.g., `-u example.com`).
* `-w`, `--wordlist`: Path to a text file containing a bulk list of targets (one per line).
* `-p`, `--ports`: Comma-separated list of ports to scan (default: `80,443`).
* `-o`, `--output`: Output file to save the scan report text (default: `results.txt`).
* `-t`, `--timeout`: Timeout in seconds for HTTP requests (default: `10`).

### Example
```bash
python3 scanner.py -w targets.txt -p 80,443,8080 -o scan_report.txt -t 5
```

## Proof of Concept (PoC) Generation
A standout feature of this scanner is its automated PoC creation. This interacts seamlessly with the included `clickjacking_PoC.html` template.

### Interaction Flow:
1. **Detection:** When the scanner identifies a URL as `[VULNERABLE]`, it triggers the `generate_poc(url)` function.
2. **Template Reading:** It reads the base template file `clickjacking_PoC.html`.
3. **Payload Injection:** It performs a regex replacement to dynamically insert the vulnerable target's URL into the template's JavaScript `targetUrl` constant.
4. **File Creation:** It extracts the network location (domain/IP) from the URL and creates a uniquely named HTML file (e.g., `poc_example.com.html`) in the active directory.
5. **Execution:** Opening this generated HTML file in a web browser will display a malicious decoy page ("CLAIM YOUR PRIZE NOW!" button) framing the vulnerable target underneath it using low CSS opacity. This visually simulates a realistic attack scenario where a user might double-click or unknowingly interact with the hidden iframe.

This instantly provides actionable proof of the vulnerability without manual HTML authoring.
