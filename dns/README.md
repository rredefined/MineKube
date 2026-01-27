# DNS Configuration Auditor

This tool is designed to help administrators audit their own domain's DNS records to ensure they are properly proxied by Cloudflare.

## Risks of Exposed IPs
If a subdomain (like `direct.example.com` or `dev.example.com`) points directly to your origin server IP instead of Cloudflare's proxy IPs, attackers can bypass your WAF and DDoS protection.

## Usage

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the audit:
   ```bash
   python audit_tool.py yourdomain.com
   ```

## Output
The tool will list your subdomains and indicate if they are:
- ✅ **Proxied**: Hidden behind Cloudflare.
- ⚠️ **DIRECT / LEAKING**: Pointing directly to a server, potentially exposing your backend.
