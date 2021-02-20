# Install ICS Tools - Linux
This script will download and install ICS tools for testing different ICS devices and protocols. It is meant to be run on a new Kali or Linux distribution.

## Actions:
* Updates system packages - requires administrative privileges
* Creates a ```Tools/ics-tools``` directory in the user's home directory to install tool repositories.
* Installs Package requirements
* Installs Python requirements
* Installs Python-based ICS Tools
* Installs Rust-based ICS Tools
* Installs Git Repos and builds several tools 

## Warning / Considerations
This script automates the installation of third-party software and tools we do not control. There is warranty or guarantee these tools are secure or do not contain malicious code. Check all installed software on your own before use.

'''USE AT YOUR OWN RISK.'''

# Tools
## Python Modules
* (pymodbus)[https://pymodbus.readthedocs.io/en/latest/]
* (bacpypes)[https://bacpypes.readthedocs.io/en/latest/]
* (cpppo)[https://github.com/pjkundert/cpppo]
* (pycomm)[https://github.com/ottowayi/pycomm3]
* (opcua)[https://github.com/FreeOpcUa/python-opcua]
* (opcua-client)[https://github.com/FreeOpcUa/opcua-client-gui]
* (python-snap7)[https://pypi.org/project/python-snap7/]
  
## Rust Cargo
* (rodbus-client)[https://github.com/stepfunc/rodbus]

## GitHub Repos
* [CHAPS](https://github.com/cutaway-security/chaps.git)
* [CutSec Tools](https://github.com/cutaway-security/cutsec_tools.git)
* [IEC61850 Library](https://github.com/mz-automation/libiec61850.git)
* [IEC61850 Tool Chain](https://github.com/smartgridadsc/IEC61850ToolChain.git)
* [Python Profinet](https://github.com/devkid/profinet.git )
* [SCADA-Profinet Network Attack](https://github.com/Chowdery/SCADA-Profinet_Network-Attack.git)
* [SCADA-Tools](https://github.com/atimorin/scada-tools.git)
* [Nmap-SCADA](https://github.com/jpalanco/nmap-scada.git )
* [Digital Bond Redpoint](https://github.com/digitalbond/Redpoint.git)
* [Industrial Exploitation Framework](https://github.com/dark-lbp/isf.git)
 * This tool requires Python 2. Pipenv shell script is generated to run the tool.

# Requirements
## Packages
* python3-pip
* python2
* pipenv
* cmake
* git
* rustc
* vim
* 
## Python
* ipython
* requests
* paramiko
* beautifulsoup4
* pysnmp
* python-nmap
* nmap
* scapy
* usb
* serial
* cryptography
* lxml
* testresources

# Tested On
* Ubuntu 20.04.2.0 LTS
* Kali 2020.4