#!/usr/bin/python3
import urllib.request
import re
import sys
import socket,struct

DEBUG = 0
#url = 'http://192.168.76.154'
url = 'http://'

def conn_GE(ip):
    if DEBUG: print('conn_GE: Connect to: %s'%(url + ip))
    try:
        resp = urllib.request.urlopen(url + ip)
    except:
        return 0
    # Make sure this is a GE Power Device
    data = resp.readlines()
    GE_DEVICE = False
    for e in data:
        if re.search('GE Power',str(e)):
            GE_DEVICE = True
            break
    if GE_DEVICE:
        if DEBUG: print("ge_GET_URL: located a GE Power device: %s"%(ip))
        return data
    else:
        if DEBUG: print("ge_GET_URL: not a GE Power device: %s"%(ip))
        return 0


def parse_GE_MSG(data):
    for e in data: 
        if re.search('Revision',str(e)): 
            # User REGEX to locate Revision String
            d = re.search('Revision   ([.0-9]*)</STRONG>',str(e)) 
            drev = d.group(1)
            if DEBUG: print('Rev: %s'%(drev)) 
        if re.search('Relay Name',str(e)): 
            # User REGEX to locate Relay Name
            d = re.search('Relay Name: </EM><STRONG>([_0-9A-Za-z]*)</STRONG>',str(e)) 
            dname = d.group(1)
            if DEBUG: print('Device Name: %s'%(dname)) 
    return {dname: drev}
       
# TODO: Update this to use netaddr module
# create IP range from CIDR range
in_range = sys.argv[1]
(ip,cidr) = in_range.split('/')
cidr = int(cidr)
host_bits = 32 - cidr
i = struct.unpack('>I',socket.inet_aton(ip))[0]
start  = ((i >> host_bits) << host_bits) + 1
end = start | ((1 << host_bits) -1)

ip_fw = {}
for i in range(start,end):
    addr = socket.inet_ntoa(struct.pack('>I',i))
    if not addr.split('.')[3]:
        continue
    if DEBUG > 2: 
        print('IP: %s'%(addr))
        continue
    else:
        if DEBUG: print('CIDR gen: Connect to: %s'%(addr))
        ge_msg = conn_GE(addr)
        if ge_msg:
            ip_fw[addr] = parse_GE_MSG(ge_msg)
        else:
            continue

if DEBUG: print('GE Firmware Range: %s'%(in_range))
if DEBUG: print('data: %s'%(ip_fw))
print('IP,Device Name,Firmware')
for k in ip_fw.keys():
    for e in ip_fw[k].keys():
        print('%s,%s,%s'%(k,e,ip_fw[k][e]))

