import os,sys
import pyshark

# User defined PCAP file
inf = sys.argv[1]

# Filter on NTLMSSP message types when processing PCAP
ntlm_auth_filter = '(ntlmssp.messagetype == 0x00000002) || (ntlmssp.messagetype == 0x00000003)'
ntlm_packets = pyshark.FileCapture(inf, display_filter=ntlm_auth_filter) 

# Main Processing
auths = {}
for p in ntlm_packets:
    # Determine if packet is SMB or RPC
    try:
        if 'SMB Layer' in str(p.layers):
            p_layer = 'SMB'
            # Use UID to track session
            auth_attempt = p.smb.uid
            mess_type    = int(p.smb.ntlmssp_messagetype,16)
        elif 'DCERPC' in str(p.layers):
            p_layer = 'DCERPC'
            # User Call ID to track session
            auth_attempt = p.dcerpc.cn_call_id
            mess_type    = int(p.dcerpc.ntlmssp_messagetype,16)
        else:
            # No SMB or DCERPC so carry on
            continue
    except:
        # Error, carry on
        continue

    # Challenge and Response Fields: https://www.mike-gualtieri.com/posts/live-off-the-land-and-crack-the-ntlmssp-protocol
    # Process Server Challenge     
    if (mess_type == 0x00000002):
        if (auth_attempt not in list(auths.keys())): 
            auths[auth_attempt] = {'username':'','hostname':'','ntlmserverchallenge':'','ntproof':'','ntresponse':''}
        if p_layer == 'SMB':
            auths[auth_attempt]['ntlmserverchallenge'] = p.smb.ntlmssp_ntlmserverchallenge.replace(':','')
        if p_layer == 'DCERPC':
            auths[auth_attempt]['ntlmserverchallenge'] = p.dcerpc.ntlmssp_ntlmserverchallenge.replace(':','')
    
    # Process Client Response
    if (mess_type == 0x00000003):
        if (auth_attempt not in list(auths.keys())):
            continue
        if p_layer == 'SMB':
            auths[auth_attempt]['username']   = p.smb.ntlmssp_auth_username
            auths[auth_attempt]['hostname']   = p.smb.ntlmssp_auth_hostname
            nt_resp                           = p.smb.ntlmssp_auth_ntresponse.replace(':','')
        if p_layer == 'DCERPC':
            auths[auth_attempt]['username']   = p.dcerpc.ntlmssp_auth_username
            auths[auth_attempt]['hostname']   = p.dcerpc.ntlmssp_auth_hostname
            nt_resp                           = p.dcerpc.ntlmssp_auth_ntresponse.replace(':','')
        # Some responses are garbage, length is a good test for issues
        if len(nt_resp) < 48: 
            del auths[auth_attempt]
            continue
        auths[auth_attempt]['ntproof']        = nt_resp[:32]
        auths[auth_attempt]['ntresponse']     = nt_resp[32:]

# Print results in PWDUMP format for hashcat
# hashcat --force -m 5600 hashes_pyshark.txt rockyou.txt
# hashcat --force -m 5600 --show hashes_pyshark.txt
for a in auths.keys():
    auth = auths[a]
    print("%s::%s:%s:%s:%s"%(auth['username'],auth['hostname'],auth['ntlmserverchallenge'],auth['ntproof'],auth['ntresponse']))
