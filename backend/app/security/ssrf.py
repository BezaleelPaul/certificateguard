import ipaddress
import socket
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class SSRFCheckResult:
    is_safe: bool
    is_dns_failure: bool = False
    reason: Optional[str] = None
    resolved_ips: List[str] = field(default_factory=list)


BLOCKED_IPV4_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (only valid as source address)
    ipaddress.ip_network("10.0.0.0/8"),         # Private-Use (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space (Carrier-grade NAT)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link Local / AWS/GCP/Azure Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # Private-Use (RFC 1918)
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("192.88.99.0/24"),     # 6to4 Relay Anycast
    ipaddress.ip_network("192.168.0.0/16"),     # Private-Use (RFC 1918)
    ipaddress.ip_network("198.18.0.0/15"),      # Network Interconnect Device Benchmark
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("255.255.255.255/32"), # Limited Broadcast
]

BLOCKED_IPV6_NETWORKS = [
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6
    ipaddress.ip_network("100::/64"),           # Discard prefix
    ipaddress.ip_network("2001:db8::/32"),      # Documentation
    ipaddress.ip_network("2002::/16"),          # 6to4 relay
    ipaddress.ip_network("fc00::/7"),           # Unique local address (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-local unicast / Cloud metadata
    ipaddress.ip_network("ff00::/8"),           # Multicast
]

BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata",
    "instance-data",
}


def is_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, str]:
    """Check if a given IP address belongs to any forbidden/private network range."""
    if ip.is_loopback:
        return True, f"Loopback IP address rejected: {ip}"
    if ip.is_private:
        return True, f"RFC1918 / Private IP address rejected: {ip}"
    if ip.is_link_local:
        return True, f"Link-local / Cloud metadata IP address rejected: {ip}"
    if ip.is_multicast:
        return True, f"Multicast IP address rejected: {ip}"
    if ip.is_reserved:
        return True, f"Reserved IP address rejected: {ip}"
    if ip.is_unspecified:
        return True, f"Unspecified IP address rejected: {ip}"

    # Explicit subnet checks
    if isinstance(ip, ipaddress.IPv4Address):
        for net in BLOCKED_IPV4_NETWORKS:
            if ip in net:
                return True, f"IP address {ip} falls inside blocked network {net}"
    elif isinstance(ip, ipaddress.IPv6Address):
        for net in BLOCKED_IPV6_NETWORKS:
            if ip in net:
                return True, f"IPv6 address {ip} falls inside blocked network {net}"

    return False, ""


def validate_url_ssrf(url: str, allow_localhost: bool = False) -> SSRFCheckResult:
    """
    Validates a URL against Server-Side Request Forgery (SSRF) attacks.
    Ensures safe protocols (HTTP/HTTPS) and blocks loopbacks, private networks,
    cloud metadata endpoints (AWS, GCP, Azure), and unresolvable/malicious targets.
    """
    if not url or not isinstance(url, str):
        return SSRFCheckResult(is_safe=False, reason="Empty or invalid URL type")

    url = url.strip()
    try:
        parsed = urlparse(url)
    except Exception as e:
        return SSRFCheckResult(is_safe=False, reason=f"URL parsing failed: {e}")

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return SSRFCheckResult(is_safe=False, reason=f"Forbidden protocol scheme '{scheme}'. Only HTTP and HTTPS are permitted.")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return SSRFCheckResult(is_safe=False, reason="Missing or invalid hostname in URL")

    # Fast-check blocked hostnames
    if not allow_localhost and (hostname in BLOCKED_HOSTNAMES or hostname.endswith(".local") or hostname.endswith(".internal")):
        return SSRFCheckResult(is_safe=False, reason=f"Target hostname '{hostname}' is a forbidden internal destination (SSRF protection)")

    # Check if hostname is directly an IP literal (e.g. 169.254.169.254 or 127.0.0.1)
    try:
        literal_ip = ipaddress.ip_address(hostname)
        if allow_localhost and (literal_ip.is_loopback or str(literal_ip) == "127.0.0.1"):
            return SSRFCheckResult(is_safe=True, resolved_ips=[str(literal_ip)])
        
        blocked, reason = is_ip_blocked(literal_ip)
        if blocked:
            return SSRFCheckResult(is_safe=False, reason=f"SSRF blocked: {reason}", resolved_ips=[str(literal_ip)])
        return SSRFCheckResult(is_safe=True, resolved_ips=[str(literal_ip)])
    except ValueError:
        pass  # Not an IP literal, proceed to DNS resolution

    # Resolve hostname via DNS to prevent DNS rebinding or domains mapping to internal IPs
    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        return SSRFCheckResult(is_safe=False, is_dns_failure=True, reason=f"DNS resolution failed for hostname '{hostname}': {e}")
    except Exception as e:
        return SSRFCheckResult(is_safe=False, is_dns_failure=True, reason=f"DNS resolution error: {e}")

    resolved_ips = []
    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        resolved_ips.append(ip_str)

        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if allow_localhost and (ip_obj.is_loopback or ip_str in ("127.0.0.1", "::1")):
                continue

            blocked, reason = is_ip_blocked(ip_obj)
            if blocked:
                return SSRFCheckResult(
                    is_safe=False,
                    reason=f"Hostname '{hostname}' resolved to blocked internal/metadata address {ip_str}: {reason}",
                    resolved_ips=resolved_ips
                )
        except ValueError:
            return SSRFCheckResult(is_safe=False, reason=f"Invalid IP address resolved: {ip_str}", resolved_ips=resolved_ips)

    return SSRFCheckResult(is_safe=True, resolved_ips=list(set(resolved_ips)))


def is_safe_url(url: str, allow_localhost: bool = False) -> bool:
    """Convenience helper returning True if the URL is safe from SSRF."""
    result = validate_url_ssrf(url, allow_localhost=allow_localhost)
    return result.is_safe
