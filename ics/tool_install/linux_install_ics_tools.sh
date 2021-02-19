#!/bin/bash
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Change to User's Home directory and create Tools Dir
echo 'Generating ICS Tools Directory at ~/Tools/ics-tools'
cd ~
TOOLDIR='./Tools/ics-tools'
mkdir -p $TOOLDIR

# Update 
echo 'Updating System Packages'
apt update && apt dist-upgrade

# Be sure Python3 Pip and other packages are installed
echo 'Apt Install Required Programs'
apt install python3-pip cmake git rustc

# Install Python Modules
## Requirements
echo 'Pip install Tool Required Python Modules'
pip install requests paramiko beautifulsoup4 pysnmp gnureadline python-nmap nmap scapy
## ICS Tools
echo 'Pip install ICS Tools'
pip install pymodbus bacpypes cpppo pycomm opcua opcua-client python-snap7

# Install Rust Modules
echo 'Rust Cargo install ICS Tools'
cargo install rodbus-client

# Git clone ICS Tools
ics_git_tools = \
https://github.com/cutaway-security/chaps.git \
https://github.com/cutaway-security/cutsec_tools.git \
https://github.com/mz-automation/libiec61850.git
https://github.com/smartgridadsc/IEC61850ToolChain.git
https://github.com/devkid/profinet.git \ 
https://github.com/Chowdery/SCADA-Profinet_Network-Attack.git \
https://github.com/atimorin/scada-tools.git \
https://github.com/jpalanco/nmap-scada.git \ 
https://github.com/digitalbond/Redpoint.git \
https://github.com/dark-lbp/isf.git \ 

for i in ics_git_tools; do git clone $i; done 

# Build Compiled Tools
cd  $TOOLDIR/libiec61850/examples
make
cd  $TOOLDIR/IEC61850ToolChain
make

# Added Path Update to ~/.zshrc or ~/.bashrc
#SHELL='~/.bashrc'
SHELL='~/.zshrc'
echo '# Update Path for local software' >> $SHELL
echo 'PATH=~/.local/bin:~/.cargo/bin:$PATH' >> $SHELL