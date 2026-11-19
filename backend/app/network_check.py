"""Layer 4: network risk.

A web/mobile app cannot fully judge if a Wi-Fi network is safe, so we use what is actually
observable: IP reputation lists, VPN/proxy/Tor flags, network type and TLS validity.
"""
import ipaddress

from . import lists

NET_BASE = {"home_wifi": 0.0, "mobile_data": 0.05, "office_wifi": 0.1, "unknown": 0.3,
            "public_wifi_secured": 0.3, "public_wifi_open": 0.5}


def _in(ip, cidrs):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(c, strict=False) for c in cidrs)


def check_network(ip=None, net_type="unknown", vpn=False, tls_ok=True):
    reasons, risks = [], []
    nl = lists.network_lists()
    if ip and _in(ip, nl["bad_ips"]):
        risks.append(0.95); reasons.append("IP address is on a malicious-IP list")
    if ip and _in(ip, nl["tor_exit"]):
        risks.append(0.8); reasons.append("Traffic comes from a Tor exit node")
    if vpn or (ip and _in(ip, nl["vpn_proxy"])):
        risks.append(0.5); reasons.append("VPN / proxy detected - real location is hidden")
    base = NET_BASE.get(net_type, 0.3)
    if net_type == "public_wifi_open":
        reasons.append("Open public Wi-Fi (no encryption) - traffic can be sniffed")
    elif net_type == "public_wifi_secured":
        reasons.append("Public Wi-Fi network")
    elif net_type == "unknown":
        reasons.append("Network type could not be identified")
    risks.append(base)
    if not tls_ok:
        risks.append(0.7); reasons.append("Secure (TLS) connection could not be verified")
    strong = len([r for r in risks if r > 0.2])
    risk = round(min(1.0, max(risks) + 0.05 * max(0, strong - 1)), 3)
    return {"risk": risk, "reasons": reasons, "net_type": net_type}
