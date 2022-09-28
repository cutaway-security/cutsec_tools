import os,sys
import pyshark
# Easy method to determine service port name by port number
from socket import getservbyname, getservbyport

# User defined PCAP file
inf = sys.argv[1]
packets = pyshark.FileCapture(inf)

# Main processing
services = {}     
for p in packets:
    # Reset fields
    src_ip,dst_ip,src_port,dst_port,trans = '','','','',''

    # Review packets for fields. Will continue if not TCP/UDP
    try:
        src_ip,dst_ip,trans = p.ip.src,p.ip.dst,p.transport_layer
        if trans == 'TCP': src_port,dst_port = int(p.tcp.srcport),int(p.tcp.dstport)
        if trans == 'UDP': src_port,dst_port = int(p.udp.srcport),int(p.udp.dstport)
    except:
        continue

    # Locate lowest service port value, this should be the listening service / application
    # Source port is lower   
    if src_port and src_port < dst_port:
        try:
            srv_name = str(src_port) + "/" + getservbyport(src_port,trans.lower()) + "/" + trans
        except:
            # Port numbers that are not associated with a known service will error
            srv_name = str(src_port) + "/" + "Unknown" + "/" + trans
        if srv_name not in str(services.keys()): services[srv_name] = []
        if src_ip not in services[srv_name]: services[srv_name].append(src_ip)

    # Destination port is lower   
    if src_port and src_port > dst_port:
        try:
            srv_name = str(dst_port) + "/" + getservbyport(dst_port,trans.lower()) + "/" + trans
        except:
            # Port numbers that are not associated with a known service will error
            srv_name = str(dst_port) + "/" + "Unknown" + "/" + trans
        if srv_name not in str(services.keys()): services[srv_name] = []
        if dst_ip not in services[srv_name]: services[srv_name].append(dst_ip)

# Target Lists by Service
for s in services.keys():
    print("%s: %s"%(s,','.join(services[s])))