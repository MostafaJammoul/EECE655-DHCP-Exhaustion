#!/usr/bin/env python3
from scapy.all import *
import time
from collections import defaultdict

iface = "eth0"
threshold = 30 # 30 leases in last minute
discovers = []
macs = set()
mac_counts = defaultdict(int)
naks = 0
score = 0

discover_small_count = 0
small_window_s = 10
max_discover_rate_small = 0.7 # 7 leases in last 10s
score_decay = 1.0
last_score_update = time.time()

leased_macs = {}
mac_last_active = {}
inactive_grace_period = 10 # 10s for client to be active after lease
inactive_thresh = 20 # No traffic for more than 20s = inactive
inactive_macs_alarm = 10

leased_ips = set()
comm_with_external = {}
per_mac_non_dhcp_pkts = {}
subnet_comm_only_grace = 15 # Wait 15s before judging new leasers
subnet_only_macs_alarm = 15 # Alarm if >= 15 clients only comm in subnet
min_consideration_pkts = 3


def count_idle(): # Helper fxn for Attack Detected alarm info
    idle_count = 0
    now = time.time()
    for mac, info in leased_macs.items():
        lease_t = info['lease_time']
        if now - lease_t < inactive_grace_period:
            continue  
        last_act = mac_last_active.get(mac, 0.0)
        if last_act < lease_t or (now - last_act) > inactive_thresh:
            idle_count += 1
    return idle_count

def count_not_external_comm(): # Helper fxn for Attack Detected alarm info
    now = time.time()
    subnet_only = []
    for mac, info in leased_macs.items():
        lease_t = info['lease_time']
        if now - lease_t < subnet_comm_only_grace:
            continue
        total_pkts = per_mac_non_dhcp_pkts.get(mac, 0)
        if total_pkts < min_consideration_pkts:
            continue
        if not comm_with_external.get(mac, False):
            subnet_only.append(mac)   
    return len(subnet_only) 

def check_packet(pkt):
    global naks, score, last_score_update, discover_small_count
    
    if not DHCP in pkt:
        return
    
    msg_type = 0
    for opt in pkt[DHCP].options:
        if opt[0] == "message-type":
            msg_type = opt[1]
            break
    
    now = time.time()
    
    diff = now - last_score_update
    if diff > 0:
        score = max(0, score-int(score_decay*diff))
        last_score_update = now
    
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
            print(f"\n[ALERT] High DISCOVER rate (last 60 seconds): {rate}/min")
            print(f"        Last MACs: {list(macs)[-3:]}")
        
        #if len(macs) > 20:
        #    if all(m[:8] == "00:0c:29" for m in list(macs)[-20:]):
        #        score += 3
        #        print(f"[ALERT] VMware pattern detected - Last 20 MAC vendors VMware")
    
    elif msg_type == 5:  # ACK 
        # BOOTP.chaddr first 6 bytes = MAC
        chaddr = pkt[BOOTP].chaddr
        client_mac = ":".join(f"{b:02x}" for b in chaddr[:6])
        leased_ip = pkt[BOOTP].yiaddr
        leased_macs[client_mac] = {'ip': leased_ip, 'lease_time': now}
        mac_last_active.setdefault(client_mac, now)
        print(f"[LEASE] {client_mac} was leased {leased_ip}")
        
        leased_ips.add(leased_ip)
        comm_with_external.setdefault(client_mac, False)
        per_mac_non_dhcp_pkts.setdefault(client_mac, 0)


                
    elif msg_type == 6:  # NAK
        naks += 1
        if naks >= 5:
            score += 3
            print(f"[ALERT] {naks} NAKs - pool exhausted")
    
    discover_small_count = max(0, sum(1 for i in discovers if i>now-small_window_s))
    small_rate = discover_small_count/max(1, small_window_s)
    
    if small_rate >= max_discover_rate_small: # More than 7 leases in last 10s
        score += 2
        print(f"[ALERT] High DISCOVER rate (last 10 seconds): {discover_small_count}/10s ")
    
    if score >= 10:
        print(f"\n{'='*50}")
        print(f"[ATTACK DETECTED]")
        print(f"  MACs: {len(macs)}")
        print(f"  Rate (last 60s): {len(discovers)}/min")
        print(f"  Rate (last {small_window_s}s): {discover_small_count}/{small_window_s}s")
        print(f"  NAKs: {naks}")
        print(f"  Idle leased clients (idle for >{inactive_thresh}s): {count_idle()}")
        print(f"  Clients without outside subnet communcation (since detetcor boot): {count_not_external_comm()}")
        
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
        print(f"[STATUS] Discovers (60s): {len(discovers)} | Discovers (10s): {discover_small_count}")
        print(f"[STATUS] MACs: {len(macs)} | NAKs: {naks} | Threat Score: {score}")
        
def sniff_activity(pkt):
    if DHCP in pkt: # Check for non-DHCP traffic
        return

    now = time.time()
    
    if Ether in pkt:
        src_mac = pkt[Ether].src
        if src_mac in leased_macs:
            mac_last_active[src_mac] = now
            
            per_mac_non_dhcp_pkts[src_mac] = per_mac_non_dhcp_pkts.get(src_mac, 0)+1

    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        for mac, info in leased_macs.items():
            if info['ip'] == src_ip: #Fallback for last active in case Eth errored out
                mac_last_active[mac] = now
                if dst_ip not in leased_ips:
                    comm_with_external[mac] = True
                elif dst_ip in leased_ips:
                    for mac_b, info_b in leased_macs.items():
                        if info_b['ip'] == dst_ip:
                            print(f"[TRAFFIC] {mac}//{src_ip} -> {mac_b}//{dst_ip}")
                    
            
            
def detect_inactivity():
    global score
    while True:
        time.sleep(5)
        now = time.time()
        idle_macs = []
        
        for mac, info in leased_macs.items():
            lease_t  = info['lease_time']
            if now - lease_t < inactive_grace_period:
                continue

            last_act = mac_last_active.get(mac, 0.0)
            if last_act < lease_t or (now - last_act) > inactive_thresh:
                idle_macs.append(mac)

        if len(idle_macs) >= inactive_macs_alarm:
            score += 10
            print(f"\n[ALERT] idle leased clients: {len(idle_macs)} (≥{inactive_macs_alarm})")
            for m in idle_macs[:5]:
                print(f"    idle: {m} ({leased_macs[m]['ip']})")
            print()
            
def detect_subnet_only():
    global score
    while True:
        time.sleep(5)
        now = time.time()
        subnet_only = []
        
        for mac, info in leased_macs.items():
            lease_t = info['lease_time']
            if now - lease_t < subnet_comm_only_grace:
                continue # Grace period for outside subnet comm
            
            total_pkts = per_mac_non_dhcp_pkts.get(mac, 0)
            if total_pkts < min_consideration_pkts: # too little packets to judge
                continue
            
            if not comm_with_external.get(mac, False):
                subnet_only.append(mac)
                
        if len(subnet_only) >= subnet_only_macs_alarm:
            score +=5
            print(f"[ALERT] Clients with subnet-only comms: {len(subnet_only)} clients")
            for m in subnet_only[:5]:
                print(f"    {m} ({leased_macs[m]['ip']})")
            print()                    

import threading
threading.Thread(target=status, daemon=True).start()
threading.Thread(target=lambda: sniff(iface=iface, store=0, prn=sniff_activity, filter="not (udp and (port 67 or port 68))"),daemon=True).start()
threading.Thread(target=detect_inactivity, daemon=True).start()
threading.Thread(target=detect_subnet_only, daemon=True).start()


print(f"[*] Monitor on {iface}")
print(f"[*] Threshold: {threshold}/min\n")

try:
    sniff(filter="udp and (port 67 or port 68)", prn=check_packet, iface=iface, store=0)
except KeyboardInterrupt:
    print(f"\n[*] Stopped")
    print(f"[*] Total MACs: {len(macs)}")
