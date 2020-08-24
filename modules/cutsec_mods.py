import sys, socket, struct
import time
import re 
import netaddr
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed

##########################
# Purpose: process a list of IP addresses ranges from CIDR
# In Parameters:
#   inCIDR: list of IP ranges - example: ['192.168.0.0/24','192.168.1.0/24']
#   queryFunc: a function that will take an IP address and return a string to be parsed
#   parseFunc: a function that will take a string and return a dictionary of data
#   header:    a comma seperated list of values to add to dictionary with key of 'header'
#   threads:   maximum number of threads to start, default: 5
#
# Return Parameters
#   resultsDict: a dictionary of parsed data
#
# TODO: 
#   Needs to include threading
# 
##########################
def processIPRange(inCIDR, queryFunc,parseFunc,header='',threads=5):    
    resultsDict = {}
    if header:
        resultsDict['header'] = header
    for net in inCIDR:
        if DEBUG: print('Processing network: %s'%(net))

        with concurrent.futures.ThreadPoolExecutor(max_workers = threads) as executor:

            future_to_dict = {executor.submit(queryFunc, str(ip)): ip for ip in netaddr.IPNetwork(net)[1:-1]}
            for future in concurrent.futures.as_completed(future_to_dict):
            url = future_to_dict[future]
            try:
                data = future.result()



        for ip in netaddr.IPNetwork(net)[1:-1]:       
            sel_msg = queryFunc(str(ip))
            if sel_msg:
                resultsDict[str(ip)] = parseFunc(sel_msg)
            else:
                continue
    return resultsDict