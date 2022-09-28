import os,sys
import pyshark

# User defined PCAP file
inf = sys.argv[1]
packets = pyshark.FileCapture(inf)

# Main Processing
interfaces = {}
for p in packets:
    # If packet doesn't have an ethernet address then just move on
    try: 
        src_ether = p.eth.src
        dst_ether = p.eth.dst
    except:
        continue
    if src_ether not in str(interfaces.keys()): interfaces[src_ether] = []
    if dst_ether not in str(interfaces.keys()): interfaces[dst_ether] = []

    # If packet doesn't have an IP address then just move on
    try:
        src_ip = p.ip.src
        dst_ip = p.ip.dst
    except:
        continue
    if src_ip not in interfaces[src_ether]: interfaces[src_ether].append(src_ip)
    if dst_ip not in interfaces[dst_ether]: interfaces[dst_ether].append(dst_ip)

# Print results
for e in interfaces.keys(): 
    if interfaces[e]: 
        print("%s: %s"%(e,interfaces[e])) 