import sys, socket, struct
import time
import re 
import netaddr

# Globals
DEBUG      = 0
#addr      = '192.168.76.39'
RANGE      = ['192.168.76.0/24','192.168.77.0/24','192.168.78.0/24']
PORT       = 23
#conn      = (addr,port)
# NOTE: Default credentials
# TODO: use user defined passwords
ID_CMD     = b'ACC\r\nOTTER\r\nID\r\n'
CONN_DELAY = .25
RESP_DELAY = .5
RECV_MSG   = 1024
FW         = 'FID'
BFW        = 'BFID'
SER        = 'SERIALNO'
TYPE       = 'type'

def conn_SEL(in_ip):
    CONN = (in_ip,PORT)
    try:
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(CONN)
        if DEBUG > 1: print('Connected: %s - %d'%(in_ip,PORT))
    except:
        if DEBUG: print('Connection failed: %s - %d'%(in_ip,PORT))
        return 0

    time.sleep(CONN_DELAY)

    if DEBUG > 1: print('Sending command: %r'%(ID_CMD))
    s.send(ID_CMD)
    time.sleep(RESP_DELAY)
    msg = s.recv(RECV_MSG)
    msg = str(msg)
    if DEBUG > 1: print('Closing connection: %s - %d'%(in_ip,PORT))
    s.close()

    if DEBUG > 1: print("IP: %s - ID: %s"%(ip,msg))
    if re.search(FW,msg):
        return msg
    else:
        return 0

def parse_SEL_MSG(in_msg):
    sel_fw = {}
    in_msg = re.sub('.*TERM','TERM',in_msg)
    # NOTE: The double slashes '\\' may not be necessary here. This needs further testing.
    lines = in_msg.split('\\r\\n')
    #lines = in_msg.split('\r\n')
    #print('lines: %r\n\n'%(lines))
    #print('lines[0]: %r'%(lines[0]))
    for l in lines:
        #print('l: %r'%(l))
        if re.search(TYPE,l):
            l_type = l.split(',')[0].replace("\"","").split('=')[1]
        if re.search(SER,l):
            l_ser = l.split(',')[0].replace("\"","").split('=')[1]
        if re.search(FW,l):
            l_fid = l.split(',')[0].replace("\"","").split('=')[1]
        if re.search(BFW,l):
            l_bfid = l.split(',')[0].replace("\"","").split('=')[1]

    # sel_fw[serial number] = [Device Type, Firmware, Boot Firmware]
    sel_fw[l_ser] = [l_type,l_fid,l_bfid]
    return sel_fw

if __name__ == '__main__':
    if len(sys.argv) > 1:
        if re.search(',',sys.argv[1]):
            RANGE = sys.argv[1].split(',')
        else:
            RANGE = [sys.argv[1]]

    ip_fw = {}
    for net in RANGE:
        if DEBUG: print('Checking for SEL devices on: %s'%(net))
        for ip in netaddr.IPNetwork(net)[1:-1]:
            '''
            try:
                if DEBUG > 1: print('Connecting to %s'%(ip))
                addr = socket.inet_ntoa(struct.pack('>I',str(ip)))
            except:
                if DEBUG > 1: print('No SEL telnet on %s'%(addr))
                continue
            '''
            sel_msg = conn_SEL(str(ip))
            if sel_msg:
                ip_fw[str(ip)] = parse_SEL_MSG(sel_msg)
            else:
                continue

    #print('SEL Firmware Range: %s'%(in_range))
    #print('ip_fw: %r'%(ip_fw))
    print('%s,%s,%s,%s,%s'%('IP Address','Serial Number','Firmware','Boot Firmware','Device'))
    for k in ip_fw.keys():
        for e in ip_fw[k].keys():
            print('%s,%s,%s,%s,%s'%(k,e,ip_fw[k][e][1],ip_fw[k][e][2],ip_fw[k][e][0]))


