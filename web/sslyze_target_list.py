#!/usr/bin/env python3
import sys
import json
import argparse

#########################
# References
#########################
# Testing for SSL-TLS (OWASP-CM-001) - https://www.owasp.org/index.php/Testing_for_SSL-TLS_(OWASP-CM-001)
# SSLScan - https://github.com/rbsec/sslscan
# SSLyze - https://github.com/nabla-c0d3/sslyze
# SSLyze Python API - 
# jq show-struct - https://raw.githubusercontent.com/ilyash/show-struct/master/show_struct.py
# Parsing JSON with jq - http://www.compciv.org/recipes/cli/jq-for-parsing-json/

#########################
# Parse Arguments
#########################
p_args = argparse.ArgumentParser(description='SSLyze JSON Parser')
p_args.add_argument(metavar='filename.json',dest='inf') 
p_args.add_argument('-t','--target_list',action="store_true",help='list targets that were scanned') 
p_args.add_argument('-c','--cert_check',action="store_true",help='list targets with weak certificates') 
p_args.add_argument('-v','--vuln_check',action="store_true",help='list targets with known SSL/TLS vulnerabilities') 

args = p_args.parse_args()

#########################
# Tool Variables
#########################
tab = '    '

#########################
# Get data from file
#########################
# inf = 'sslyze_10.142.207.32-27_open_20191122.json'
#inf = sys.argv[1]
try:
    d = json.loads(open(args.inf,'r').read())
except:
    print("%s: error opening file %s"%(sys.argv[0],args.inf))
    sys.exit()

#########################
# List servers and ports in scan
#########################
if args.target_list:
    print("\n### Target List ###")
    for e in d['accepted_targets']:
        print('%s:%s'%(e['server_info']['hostname'],e['server_info']['port']))

#########################
# Processing Variables
#########################
cipher_list = [
    "sslv2",
    "sslv3",
    "tlsv1",
    "tlsv1_1",
    "tlsv1_2",
    "tlsv1_2"
]
min_cipher_index  = 4
min_cipher_bitcnt = 128
weak_cert_list = {}

vuln_test_list = [
    'compression', 
    'fallback', 
    'heartbleed', 
    'openssl_ccs', 
    'reneg', 
    'resum', 
    'robot'
]
vuln_test_list_names = {
    'compression':'Compression Vulnerability - CRIME', 
    'fallback':'Fallback Vulnerability - POODLE', 
    'heartbleed':'Heartbleed Vulnerability - HEARTBLEED', 
    'openssl_ccs':'CCS Injection Vulnerability', 
    'reneg':'TLS/SSL Renegotiation Vulnerability',
    'resum':'Resumption Vulnerability',
    'robot':'Oracle Threat Vulnerability - ROBOT'
}
vuln_list = {}

#########################
# Process JSON data
#########################
for e in d['accepted_targets']:
    server_name = '%s:%s'%(e['server_info']['hostname'],e['server_info']['port'])

    #########################
    # Identify servers that accept weak certificate family and bit length
    #########################
    for cipher in cipher_list:
        cnt = len(d['accepted_targets'][0]['commands_results'][cipher]['accepted_cipher_list'])
        if cnt:                
            certs = d['accepted_targets'][0]['commands_results'][cipher]['accepted_cipher_list']
            for c in certs:
                if (c['key_size'] < min_cipher_bitcnt) or (cipher_list.index(cipher) < min_cipher_index):
                    weak_cert = '%s.%s.%sbits'%(cipher,c['openssl_name'],c['key_size'])
                    if weak_cert in weak_cert_list.keys():
                        weak_cert_list[weak_cert].append(server_name)
                    else:
                        weak_cert_list[weak_cert] = [server_name]

    #########################
    # Identify servers that accept known vulnerabilities
    #########################
    # TODO: Compression - Not Implemented, yet.
    # Heartbleed
    if d['accepted_targets'][0]['commands_results']['heartbleed']['is_vulnerable_to_heartbleed']:
        if 'heartbleed' in vuln_list.keys():
            vuln_list['heartbleed'].append(server_name)
        else:
            vuln_list['heartbleed'] = [server_name]
    # CCS Injection
    if d['accepted_targets'][0]['commands_results']['openssl_ccs']['is_vulnerable_to_ccs_injection']:
        if 'openssl_ccs' in vuln_list.keys():
            vuln_list['openssl_ccs'].append(server_name)
        else:
            vuln_list['openssl_ccs'] = [server_name]
    # TODO: TLS/SSL Renegotiation - Not Implemented, yet.
    # TODO: Resumption - Not Implemented, yet.
    # Oracle Threat
    if d['accepted_targets'][0]['commands_results']['robot']['robot_result_enum'] != 'NOT_VULNERABLE_NO_ORACLE':
        if 'robot' in vuln_list.keys():
            vuln_list['robot'].append(server_name)
        else:
            vuln_list['robot'] = [server_name]

# Print cert results
if args.cert_check:
    print("\n### Certificate Issue List ###")
    for e in weak_cert_list.keys():
        # Family.Cert.BitLength
        print("%s%s"%(tab*0,e))
        # List of vulnerable systems by IP:Port
        print("%s%s\n"%(tab*1,','.join(weak_cert_list[e])))

# Print vuln results
if args.vuln_check:
    print("\n### Vulnerability Issue List ###")
    for e in vuln_list.keys():
        # Vuln Family
        print("%s%s"%(tab*0,vuln_test_list_names[e]))
        # List of vulnerable systems by IP:Port
        print("%s%s\n"%(tab*1,','.join(vuln_list[e])))
