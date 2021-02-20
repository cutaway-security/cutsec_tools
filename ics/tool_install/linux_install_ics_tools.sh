#!/bin/bash

##########
# Name: linux_install_ics_tools.sh
# Purpose: Install and configure ICS Tools on a linux system.
# Author: Don C. Weber (@cutaway) - Cutaway Security, LLC.
# 
# WARNING: Automated install of third-party software and tools we do not control.
# WARNING: No warranty or guarantee these tools are secure or do not contain malicious code.
# WARNING: Check all installed software on your own before use.
# WARNING: USE AT YOUR OWN RISK.
##########

##########
## TODO: Add test for Ubuntu and Kali distros (to handle differences)
## TODO: Add test for distro versions and ask user to continue
## TODO: Add bypass variables
## TODO: Add test to determine if IEC61850 tools were not updated and have already been compiled
## TODO: Add test to determine if IEC61850 tools were updated and compile
## TODO: Setup Configuration File
### TODO: APT packages
### TODO: PIP modules
### TODO: PIP ICS modules
### TODO: GitHub Repos
##########

##########
# Details
##########
echo 'Install Common ICS Tools on Linux Systems'
echo '   linux_install_ics-tools.sh brought to you by Cutaway Security, LLC.'
echo '   Author: Don C. Weber (@cutaway)'
echo 'WARNING: Automated install of third-party software and tools we do not control.'
echo 'WARNING: No warranty or guarantee these tools are secure or do not contain malicious code.'
echo 'WARNING: Check all installed software on your own before use.'
echo 'WARNING: USE AT YOUR OWN RISK.'
echo
INSTALL_COMMENT="### CUTSEC Installer: "
read -n1 -s -r -p $'Press Y to continue...\n' key

if [ "$key" = 'Y' ]; then
    echo 'Excellent.... Continuing... Enjoy....'
else
    echo 'Exiting....'
    exit 0
fi

##########
# Change to User's Home directory and create Tools Dir
##########
echo $INSTALL_COMMENT'Generating ICS Tools Directory at ~/Tools/ics-tools'
cd $HOME
TOOLDIR=$HOME'/Tools/ics-tools'
if [[ -d $TOOLDIR ]]
then
    echo $INSTALL_COMMENT$TOOLDIR" directory already exists! Skipping..."
else
    mkdir -p $TOOLDIR
fi
cd $TOOLDIR

##########
# Update System
##########
echo $INSTALL_COMMENT'Updating System Packages'
sudo apt update && sudo apt -y dist-upgrade

##########
# Be sure Python3 Pip and other packages are installed
##########
echo $INSTALL_COMMENT'Apt Install Required Programs'
PYTHON_MODULES='
    python3-pip
    python2
    pipenv
    cmake
    git
    rustc
    vim
'

sudo apt -y install $PYTHON_MODULES

##########
# Install Python Modules
##########
## Requirements
echo $INSTALL_COMMENT'Pip install Tool Required Python Modules'
PIP_MODULES='
    ipython
    requests
    paramiko
    beautifulsoup4
    pysnmp
    python-nmap
    nmap
    scapy
    usb
    serial
    cryptography
    lxml
    testresources
'

pip3 install $PIP_MODULES

## ICS Tools
echo $INSTALL_COMMENT'Pip install ICS Tools'
PIP_ICS_TOOLS='
    pymodbus
    bacpypes
    cpppo
    pycomm3
    opcua
    opcua-client
    python-snap7
'

pip3 install $PIP_ICS_TOOLS

##########
# Install Rust Modules
##########
echo $INSTALL_COMMENT'Rust Cargo install ICS Tools'
RUST_ICS_TOOLS='
    rodbus-client
'
cargo install $RUST_ICS_TOOLS

##########
# Git clone ICS Tools
##########
echo $INSTALL_COMMENT'Downloading or updating GitHub Repos'
ICS_GIT_TOOLS='
    https://github.com/danielmiessler/SecLists.git
    https://github.com/cutaway-security/chaps.git
    https://github.com/cutaway-security/cutsec_tools.git
    https://github.com/mz-automation/libiec61850.git
    https://github.com/smartgridadsc/IEC61850ToolChain.git
    https://github.com/devkid/profinet.git 
    https://github.com/Chowdery/SCADA-Profinet_Network-Attack.git
    https://github.com/atimorin/scada-tools.git
    https://github.com/jpalanco/nmap-scada.git 
    https://github.com/digitalbond/Redpoint.git
    https://github.com/dark-lbp/isf.git 
    https://github.com/bitsadmin/wesng.git
'

# Loop through each repo and check if we have downloaded it.
for REPO in $ICS_GIT_TOOLS; do 
    # Reset into Tools directory
    cd $TOOLDIR
    # Get last field in URL to check for directory
    LURL=${REPO##*/}
    RDIR=`echo $LURL | cut -d'.' -f1`
    if [ -d $RDIR ]; then
        echo $INSTALL_COMMENT$RDIR" repo already exists! Pulling..."
        cd $RDIR
        git pull
        cd $TOOLDIR
    else
        echo $INSTALL_COMMENT$RDIR" cloning..."
        git clone $REPO; 
    fi
done 

##########
# Build Tools that need to be Compiled
##########
echo $INSTALL_COMMENT'Compiling IEC61850 Tools'
cd  $TOOLDIR/libiec61850/examples
make clean
make
cd  $TOOLDIR/IEC61850ToolChain
make clean
make

##########
# ISF requires Python 2.7. Must use PIPENV and generate a script to run correctly.
##########
echo $INSTALL_COMMENT'Setting up Industrial Exploit Framework'
# Don't run if clone failed
if [ -d $TOOLDIR/isf ]; then
    cd $TOOLDIR/isf
    # Don't run if Pipfile is present
    if [ ! -f $TOOLDIR/isf/Pipfile ]; then
        pipenv --two install -r requirements.txt
        echo 'pipenv run ./isf.py' > isf_RUNME_PIPENV.sh
        chmod 755 isf_RUNME_PIPENV.sh
    fi
fi

##########
# Added Path Update to ~/.zshrc or ~/.bashrc
##########
echo $INSTALL_COMMENT'Configuring Shell Resource files'
SHFILE='
    bashrc
    zshrc
'
for e in $SHFILE; do
    SHELL=$HOME'/.'$e;
    # Tag to help know if the shell resource files have been modified for PATH
    PTAG='CUTSEC_ICSTOOLS'
    # Updated PATH
    PNEW='export PATH='$HOME'/.local/bin:'$HOME'/.cargo/bin:$PATH'
    # Check for each shell file and update
    if [ -f $SHELL ]; then
        # Don't add if it is already there
        if grep -q ICSTOOLS $SHELL; then
            # Make a backup of the current shellrc file
            cp $SHELL $SHELL"_"$(date +"%Y%m%d%H%M").bk
            echo ' ' >> $SHELL
            echo '# '$PTAG': Update Path for local software' >> $SHELL;
            echo $PNEW >> $SHELL;
        fi
    fi
done

##########
# Add Screen and VIM Resource files to configure correctly
##########
echo $INSTALL_COMMENT'Configuring Screen and VIM resources files'
cd $HOME
## .screenrc sets up better visual and tabbed sessions
if [ ! -f '.screenrc' ]; then
    wget https://gist.githubusercontent.com/cutaway/0ddfd31d993bf2f71378/raw/ecf390952c1196e650a4dd71ac484752e43ef5b2/.screenrc
fi
## .vimrc sets up tabbed editing
if [ ! -f '.screenrc' ]; then
    wget https://gist.githubusercontent.com/cutaway/d69c1dcc868eb1896998/raw/3126fdf17cd911b1ead61b295d76dfb541ada26d/.vimrc
fi

##########
# Complete
##########
echo 'ICS Tools Installed. Happy Hunting....'
echo '   Be sure to double check that the PATH env was updated correctly.'
echo '   Some tools may not run due to Python 2.7 and Python 3 issues. Check each tools and update as necessary.'
echo '   linux_install_ics-tools.sh brought to you by Cutaway Security, LLC.'
echo '   Author: Don C. Weber (@cutaway)'
