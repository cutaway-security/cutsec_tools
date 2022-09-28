import os,sys
import pyshark

# User defined PCAP file
inf = sys.argv[1]                                            
packets = pyshark.FileCapture(inf)                                 

# Main Process
protos = []                                                        
for p in packets: 
    pl = '' 
    # Test for protocol layers beyond TCP/UDP
    if len(p.layers) > 3: pl = str(p.layers[3]).split(':')[0] 
    if pl and pl not in protos: protos.append(pl) 

# Print Protocol Layers
for pr in protos: 
    print(pr) 