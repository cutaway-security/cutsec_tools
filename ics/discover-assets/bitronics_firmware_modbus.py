import sys
import asyncio
import time
import netaddr
from pymodbus.client.sync import ModbusTcpClient
from pymodbus.constants import Defaults

###################
# Globals
###################
DEBUG = 0
BT_FW = {}
RANGE = ['192.168.1.0/24','192.168.2.0/24','192.168.3.0/24']
#RANGE = ['192.168.1.0/24']
PORT  = 502
Defaults.Timeout = .25
# Product ID Map
# TODO: Add more devices
BT_PID_MAP = {
    602:'MX50',
}
VENDOR = 'Bitronics'

async def get_bt_firmware(client,ip):
    unit     = int(ip.split('.')[-1])
    fw_addr  = 72
    fw_size  = 1
    pid_addr = 70
    pid_size = 1
    if DEBUG > 1: print('get_bt_firmware: retrieving fwNum')
    fwNum = client.read_holding_registers(fw_addr,fw_size,unit=unit)
    if DEBUG > 1: print('get_bt_firmware: fwNum: %s'%(fwNum.registers))
    try:
        fwNum  = fwNum.registers[0]
        if not fwNum or fwNum < 2200 or fwNum > 3000:
            return
        if DEBUG > 1: print('get_bt_firmware: retrieving product id')
        pidNum = client.read_holding_registers(pid_addr,pid_size,unit=unit)
        if DEBUG > 1: print('get_bt_firmware: serNum: %s'%(pidNum.registers))
        pidNum = BT_PID_MAP[pidNum.registers[0]]
        #pidNum = pidNum.registers[0]
    except:
        pass
    BT_FW[ip] = {pidNum:fwNum}
    return
    
async def loop_clients(inRange):
    for net in inRange:
        if DEBUG: print('Checking for Bitrinics devices on: %s'%(net))
        for ip in netaddr.IPNetwork(net)[1:-1]:
            try:
                if DEBUG > 1: print('Connecting to %s'%(ip))
                mbclient = ModbusTcpClient(str(ip),PORT)
                if DEBUG > 1: print('Detected modbus on %s'%(ip))
                await get_bt_firmware(mbclient,str(ip))
            except:
                if DEBUG > 1: print('No modbus on %s'%(ip))
                continue

if __name__ == '__main__':
    if len(sys.argv) > 2:
        RANGE = sys.argv[1]
    loop = asyncio.new_event_loop()
    loop.run_until_complete( loop_clients(RANGE))
    loop.close()
    
    # Print output to STDOUT
    print('%s,%s,%s,%s'%('IP Address','Vendor','Device','Firmware'))
    for k in BT_FW.keys():
        for e in BT_FW[k]:
            print('%s,%s,%s,%s'%(k,VENDOR,e,BT_FW[k][e]))
