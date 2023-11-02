#!/usr/bin/env zsh
# Converted to ZSH for Kali because this script requires sourcing $HOME/.zshrc after APT install

##########
# Name: linux_install_ics_tools.sh
# Purpose: Install and configure ICS Tools on a linux system.
# Author: Don C. Weber (@cutaway) - Cutaway Security, LLC.
#
# Special Thanks: Andy Laman (@andylaman) - https://www.sans.org/profiles/andrew-laman/
# 
# WARNING: Automated install of third-party software and tools we do not control.
# WARNING: No warranty or guarantee these tools are secure or do not contain malicious code.
# WARNING: Check all installed software on your own before use.
# WARNING: USE AT YOUR OWN RISK.
##########

##########
## TODO: Detect shell and source proper resource file
## TODO: Add test for Ubuntu and Kali distros (to handle differences)
## TODO: Add test for distro versions and ask user to continue
## TODO: Setup Configuration File
### TODO: Add bypass variables
### TODO: APT packages
### TODO: GitHub Repos
##########

##########
# Details
##########
_ITEM="[-] "
_IMPORTANT="[!] "
_QUESTION="[?] "
_INSTALL_COMMENT="### CUTSEC Installer: "
echo $_ITEM'Install Common ICS Zeek Plugins and Packages on Linux Systems'
echo $_ITEM'   linux_install_ics-zeek.zsh brought to you by Cutaway Security, LLC.'
echo $_ITEM'   Author: Don C. Weber (@cutaway)'
echo $_IMPORTANT'WARNING: Automated install of third-party software and tools we do not control.'
echo $_IMPORTANT'WARNING: No warranty or guarantee these tools are secure or do not contain malicious code.'
echo $_IMPORTANT'WARNING: Check all installed software on your own before use.'
echo $_IMPORTANT'WARNING: USE AT YOUR OWN RISK.'
echo
read -k -s "key?$_QUESTION Press Y to continue..."

echo
if [ "$key" = 'Y' ]; then
    echo $_ITEM'Excellent.... Continuing... Enjoy....'
else
    echo $_ITEM'Exiting....'
    exit 0
fi

##########
# Change to User's Home directory and create Tools Dir
##########
echo $_ITEM$_INSTALL_COMMENT'Generating ICS Tools Directory at ~/Tools/ics-zeek'
cd $HOME
TOOLDIR=$HOME'/Tools/ics-zeek'
if [[ -d $TOOLDIR ]]
then
    echo $_ITEM$_INSTALL_COMMENT$TOOLDIR" directory already exists! Skipping..."
else
    mkdir -p $TOOLDIR
fi
cd $TOOLDIR

##########
# Update System
##########
echo $_ITEM$_INSTALL_COMMENT'Updating System Packages'
sudo apt update && sudo apt -y dist-upgrade


##########
# Be sure Zeek building packages are installed
##########
echo $_ITEM$_INSTALL_COMMENT'Apt Install Required Programs'
APT_PACKAGES=(
'python3-pip'
'pipenv'
'make' 
'cmake'
'git'
'vim'
'zeek'
'zkg'
'zeek-dev'
'binpac' 
'libcaf-dev' 
'libbroker-dev' 
'bifcl'
'gcc' 
'g++' 
'flex' 
'bison' 
'libpcap-dev'
'libssl-dev' 
'python-dev' 
'swig' 
'zlib1g-dev'
)

sudo apt -y install $APT_PACKAGES
# Update shell after install to recognize new packages
source $HOME'/.zshrc'

##########
# Git clone ICS Tools
##########
echo $_ITEM$_INSTALL_COMMENT'Downloading or updating GitHub Repos'
ICS_GIT_TOOLS=(
'https://github.com/mitre-attack/bzar.git'
'https://github.com/klehigh/find_smbv1.git'
'https://github.com/micrictor/smbfp.git'
'https://github.com/cisagov/icsnpp-bacnet.git'
'https://github.com/cisagov/icsnpp-bsap-ip.git'
'https://github.com/cisagov/icsnpp-bsap-serial.git'
'https://github.com/cisagov/icsnpp-dnp3.git'
'https://github.com/cisagov/icsnpp-enip'
'https://github.com/cisagov/icsnpp-ethercat'
'https://github.com/cisagov/icsnpp-modbus.git'
'https://github.com/cisagov/icsnpp-opcua-binary'
'https://github.com/amzn/zeek-plugin-profinet.git'
'https://github.com/amzn/zeek-plugin-enip.git'
'https://github.com/amzn/zeek-plugin-s7comm.git'
'https://github.com/amzn/zeek-plugin-bacnet.git'
'https://github.com/amzn/zeek-plugin-tds.git'
)

# Loop through each repo and check if we have downloaded it.
for REPO in $ICS_GIT_TOOLS; do 
    # Reset into Tools directory
    cd $TOOLDIR
    # Get last field in URL to check for directory
    LURL=${REPO##*/}
    RDIR=`echo $LURL | cut -d'.' -f1`
    if [ -d $RDIR ]; then
        echo $_ITEM$_INSTALL_COMMENT$RDIR" repo already exists! Pulling..."
        cd $RDIR
        git pull
        cd $TOOLDIR
    else
        echo $_ITEM$_INSTALL_COMMENT$RDIR" cloning..."
        git clone $REPO; 
    fi
    # If it is an Amazon Zeek Plugin, we have to compile. Benefit is it gets installed as plugin and not package.
    if [[ $RDIR = 'zeek-plugin-'* ]] ; then
        echo $_ITEM$_INSTALL_COMMENT$RDIR" is an Amazon Zeek plugin. Configuring and installing...."
        cd $RDIR
        ./configure && make && sudo make install && make clean
        cd $TOOLDIR
    fi
done 


##########
# Git clone ICS Tools
##########
# Prepare a load.zeek file to load packages

echo $_ITEM$_INSTALL_COMMENT'Generating load.zeek file...'
LOADZEEK="
@load ${TOOLDIR}/bzar/scripts/
@load ${TOOLDIR}/find_smbv1/scripts/
@load ${TOOLDIR}/smbfp/scripts/
@load ${TOOLDIR}/icsnpp-bacnet/scripts/
@load ${TOOLDIR}/icsnpp-bsap-ip/scripts/
@load ${TOOLDIR}/icsnpp-bsap-serial/scripts/
@load ${TOOLDIR}/icsnpp-dnp3/scripts/
@load ${TOOLDIR}/icsnpp-enip/scripts/
@load ${TOOLDIR}/icsnpp-ethercat/scripts/
@load ${TOOLDIR}/icsnpp-modbus/scripts/
@load ${TOOLDIR}/icsnpp-opcua-binary/scripts/
"
cd $TOOLDIR
echo $LOADZEEK >load.zeek


##########
# Complete
##########
echo $_ITEM'ICS Zeek Tools Installed. Happy Hunting....'
echo $_ITEM'   Analyze PCAP files using: zeek -Cr <pcap> $HOME/Tools/ics-zeek/load.zeek'
echo $_ITEM'   linux_install_zeek-tools.zsh brought to you by Cutaway Security, LLC.'
echo $_ITEM'   Author: Don C. Weber (@cutaway)'
