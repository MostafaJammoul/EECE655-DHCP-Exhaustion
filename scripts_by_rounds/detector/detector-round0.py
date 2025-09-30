#!/usr/bin/env python3
from scapy.all import *
import time
from collections import defaultdict

iface = "eth0"
threshold = 10
discovers = []
macs = set()
mac_counts = defaultdict(int)
naks = 0
score = 0

def check_packet(pkt):
    global naks, score
    
    if not DHCP in pkt:
        return
    
    msg_type = 0
    for opt in pkt[DHCP].options:
        if opt[0] == "message-type":
            msg_type = opt[1]
            break
    
    now = time.time()
    
    if msg_type == 1:  # DISCOVER
        discovers.append(now)
        mac = pkt[Ether].src
        macs.add(mac)
        mac_counts[mac] += 1
        
        # Clean old
        while discovers and discovers[0] < now - 60:
            discovers.pop(0)
        
        rate = len(discovers)
        
        if rate > threshold:
            score += 2
            print(f"\n[ALERT] High rate: {rate}/min")
            print(f"        Last MACs: {list(macs)[-3:]}")
        
        if len(macs) > 20:
            if all(m[:8] == "00:0c:29" for m in list(macs)[-20:]):
                score += 3
                print(f"[ALERT] VMware pattern detected")
                
    elif msg_type == 6:  # NAK
        naks += 1
        if naks >= 5:
            score += 3
            print(f"[ALERT] {naks} NAKs - pool exhausted")
    
    if score >= 10:
        print(f"\n{'='*50}")
        print(f"[ATTACK DETECTED]")
        print(f"  MACs: {len(macs)}")
        print(f"  Rate: {len(discovers)}/min")
        print(f"  NAKs: {naks}")
        
        bad_macs = [m for m,c in mac_counts.items() if c > 3]
        if bad_macs:
            print(f"\n  Suspicious MACs:")
            for m in bad_macs[:5]:
                print(f"    {m}")
        
        print(f"{'='*50}\n")
        score = 0

def status():
    while True:
        time.sleep(10)
        print(f"[STATUS] Discovers: {len(discovers)} | MACs: {len(macs)} | NAKs: {naks}")

import threading
t = threading.Thread(target=status, daemon=True)
t.start()

print(f"[*] Monitor on {iface}")
print(f"[*] Threshold: {threshold}/min\n")

try:
    sniff(filter="udp and (port 67 or port 68)", prn=check_packet, iface=iface, store=0)
except KeyboardInterrupt:
    print(f"\n[*] Stopped")
    print(f"[*] Total MACs: {len(macs)}")
