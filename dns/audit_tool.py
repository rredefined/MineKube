import dns.resolver
import requests
import ipaddress
import sys
import socket

# Configuration
COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'dev', 'webmail', 'direct', 
    'admin', 'cpanel', 'test', 'staging', 'api'
]
CF_IPV4_URL = "https://www.cloudflare.com/ips-v4"
CF_IPV6_URL = "https://www.cloudflare.com/ips-v6"

def get_cloudflare_ranges():
    """Fetches current Cloudflare IP ranges."""
    print("Fetching Cloudflare IP ranges...")
    try:
        cf_ips = []
        r4 = requests.get(CF_IPV4_URL, timeout=10)
        if r4.status_code == 200:
            for line in r4.text.splitlines():
                cf_ips.append(ipaddress.ip_network(line.strip()))
        
        r6 = requests.get(CF_IPV6_URL, timeout=10)
        if r6.status_code == 200:
            for line in r6.text.splitlines():
                cf_ips.append(ipaddress.ip_network(line.strip()))
                
        return cf_ips
    except Exception as e:
        print(f"Error fetching Cloudflare IPs: {e}")
        sys.exit(1)

def is_cloudflare_ip(ip_str, cf_ranges):
    """Checks if an IP address belongs to Cloudflare."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for network in cf_ranges:
            if ip in network:
                return True
        return False
    except ValueError:
        return False

def resolve_domain(hostname):
    """Resolves A and AAAA records for a hostname."""
    ips = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
    
    try:
        answers = resolver.resolve(hostname, 'A')
        for rdata in answers:
            ips.append(rdata.to_text())
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout):
        pass
    except Exception:
        pass
        
    return ips

def audit_domain(domain):
    """Main audit logic for the domain and subdomains."""
    print(f"\n--- Starting DNS Audit for: {domain} ---\n")
    
    cf_ranges = get_cloudflare_ranges()
    subdomains_to_check = ['@'] + COMMON_SUBDOMAINS 
    
    print(f"{'Target':<30} | {'IP Address':<20} | {'Status'}")
    print("-" * 75)

    found_targets = []

    for sub in subdomains_to_check:
        if sub == '@':
            hostname = domain
        else:
            hostname = f"{sub}.{domain}"
        
        ips = resolve_domain(hostname)
        
        if not ips:
            # Silence output for non-existent subdomains to keep report clean
            continue

        for ip in ips:
            is_cf = is_cloudflare_ip(ip, cf_ranges)
            status = "✅ Proxied (Cloudflare)" if is_cf else "⚠️  DIRECT / LEAKING?"
            print(f"{hostname:<30} | {ip:<20} | {status}")
            found_targets.append((hostname, ip))
            
    print("\n--- Audit Complete ---")
    print("If you see 'DIRECT / LEAKING', these records expose the server IP.")
    print("Attackers can use these IPs to bypass Cloudflare protection.\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python audit_tool.py <domain.com>")
        sys.exit(1)
    
    target_domain = sys.argv[1]
    audit_domain(target_domain)
