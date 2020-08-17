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
GE_FW = {}
RANGE = ['192.168.76.0/24','1192.168.77.0/24','192.168.78.0/24']
#RANGE = ['192.168.76.0/24']
PORT  = 502
Defaults.Timeout = .25
# Product ID Map
GE_PID_MAP = {
    16695:'C30',
    16696:'C60',
    16706:'D60',
    16710:'C70',
    16712:'F60',
    16713:'F35',
    16968:'T60'
}
VENDOR = 'GE'

async def get_ge_firmware(client,ip):
    unit     = int(ip.split('.')[-1])
    fw_addr  = 0x0002
    fw_size  = 1
    ser_addr = 0x0010
    ser_size = 6
    pid_addr = 0x0
    pid_size = 1
    if DEBUG > 1: print('get_ge_firmware: retrieving fwNum')
    fwNum = client.read_holding_registers(fw_addr,fw_size,unit=unit)
    if DEBUG > 1: print('get_ge_firmware: fwNum: %s'%(fwNum.registers))
    try:
        fwNum  = fwNum.registers[0]
        if not fwNum or fwNum < 750 or fwNum > 800:
            return
        if DEBUG > 1: print('get_ge_firmware: retrieving serNum')
        serNum = client.read_holding_registers(ser_addr,ser_size,unit=unit)
        if DEBUG > 1: print('get_ge_firmware: serNum: %s'%(serNum.registers))
        serNum = serNum.registers
        if DEBUG > 1: print('get_ge_firmware: retrieving product id')
        pidNum = client.read_holding_registers(pid_addr,pid_size,unit=unit)
        if DEBUG > 1: print('get_ge_firmware: serNum: %s'%(pidNum.registers))
        pidNum = GE_PID_MAP[pidNum.registers[0]]
    except:
        pass
    r = ''
    for e in serNum:
        r += chr(int(hex(e)[2:][:2],16))
        r += chr(int(hex(e)[2:][2:],16))
    serNum = r
    GE_FW[ip] = {serNum:[fwNum,pidNum]}
    return
    
async def loop_clients(inRange):
    for net in inRange:
        if DEBUG: print('Checking for GE devices on: %s'%(net))
        for ip in netaddr.IPNetwork(net)[1:-1]:
            try:
                if DEBUG > 1: print('Connecting to %s'%(ip))
                mbclient = ModbusTcpClient(str(ip),PORT)
                if DEBUG > 1: print('Detected modbus on %s'%(ip))
                await get_ge_firmware(mbclient,str(ip))
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
    print('%s,%s,%s,%s,%s'%('IP Address','Vendor','Device','Firmware','Serial Number'))
    for k in GE_FW.keys():
        for e in GE_FW[k]:
            print('%s,%s,%s,%s,%s'%(k,VENDOR,GE_FW[k][e][1],GE_FW[k][e][0],e))
