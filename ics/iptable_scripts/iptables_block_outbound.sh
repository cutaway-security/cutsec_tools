#!/bin/bash
#########################
# Purpose: deny all outbound traffic on an interface that is 
#          going to be used for sniffing via TCPDump / Tshark /
#          Wireshark. This is required for direct sniffing, 
#          sniffing using a tap like SharkTapUSB, or using a 
#          spanned port.
#
# Usage: 
#     Start blocking: ./iptables_block_outbound.sh eth0 start
#     Stop blocking:  ./iptables_block_outbound.sh eth0 stop
#########################

intface=$1
mode=$2
cmds='iptables ip6tables'

for i in $cmds; do
    echo ----------------------
    echo List $i
    echo ----------------------
    /usr/sbin/$i -L
    echo ----------------------
    echo
    echo ----------------------
    echo Flush $i
    echo ----------------------
    /usr/sbin/$i -F
    echo
    if [[ $mode == 'start' ]]; then
        echo ----------------------
        echo Blocking Traffic - $i
        echo ----------------------
        /usr/sbin/$i -A OUTPUT -o $intface -j DROP
        echo ----------------------
        echo
    fi
    echo ----------------------
    echo List Result $i
    echo ----------------------
    /usr/sbin/$i -L
    echo ----------------------
    echo
done
