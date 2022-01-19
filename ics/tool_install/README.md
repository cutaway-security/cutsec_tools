__Table of Contents__
* [ICS Tool Installation Script](https://github.com/cutaway-security/cutsec_tools/tree/master/ics/tool_install#install-ics-tools---linux)
* [Zeek Package Install Script](https://github.com/cutaway-security/cutsec_tools/tree/master/ics/tool_install#zeek-package-install-script) 

# ICS Tool Installation Script
## Install ICS Tools - Linux
This script will download and install ICS tools for testing different ICS devices and protocols. It is meant to be run on a new Kali or Linux distribution.

### Actions:
* Updates system packages - requires administrative privileges
* Creates a ```~/Tools/ics-tools``` directory in the user's home directory to install tool repositories.
* Installs Package requirements
* Installs Python requirements
* Installs Python-based ICS Tools
* Installs Rust-based ICS Tools
* Installs Git Repos and builds several tools 

### Warning / Considerations
This script automates the installation of third-party software and tools we do not control. There is NO warranty or guarantee these tools are secure or do not contain malicious code. Check all installed software on your own before use.

**USE AT YOUR OWN RISK.**

### References
* [ITI ICS-Security-Tools](https://github.com/ITI/ICS-Security-Tools) - many of these tools were noted in these lists.

## How to Run
* Use wget to download [raw script](https://raw.githubusercontent.com/cutaway-security/cutsec_tools/master/ics/tool_install/linux_install_ics_tools.sh)
* Change permissions of script: ```chmod 755 linux_install_ics_tools.sh```
* Run script: ```./linux_install_ics_tools.sh```
  * NOTE: Do **NOT** run as administrator. The script will prompt for admin password when ```apt``` is run. All other commands will be run as the user.  

### Tools
#### Python Modules
* [pymodbus](https://pymodbus.readthedocs.io/en/latest/) - Modbus
* [ctmodbus](https://github.com/ControlThings-io/ctmodbus) - Modbus
* [bacpypes](https://bacpypes.readthedocs.io/en/latest/) - BACnet
* [cpppo](https://github.com/pjkundert/cpppo) - EtherNet/IP CIP
* [pycomm3](https://github.com/ottowayi/pycomm3) - EtherNet/IP CIP
* [opcua](https://github.com/FreeOpcUa/python-opcua) - OPC UA
* [opcua-client](https://github.com/FreeOpcUa/opcua-client-gui) - OPC UA
* [python-snap7](https://pypi.org/project/python-snap7/) - Siemens 7
* [ctserial](https://github.com/ControlThings-io/ctserial) - Serial
  
#### Rust Cargo
* [rodbus-client](https://github.com/stepfunc/rodbus) - Modbus

#### GitHub Repos
* [SecLists](https://github.com/danielmiessler/SecLists.git) - General files and data
  * This might double up this repo on a Kali box since it might be installed or someone might install via APT 
* [CHAPS](https://github.com/cutaway-security/chaps.git) - Windows Configuration
* [CutSec Tools](https://github.com/cutaway-security/cutsec_tools.git) - General Scripts
* [IEC61850 Library](https://github.com/mz-automation/libiec61850.git) - IEC 61850 for Manufacturing Message Specification and Goose
* [IEC61850 Tool Chain](https://github.com/smartgridadsc/IEC61850ToolChain.git) - IEC 61850 for Manufacturing Message Specification and Goose
* [Python Profinet](https://github.com/devkid/profinet.git) - Profinet
* [SCADA-Profinet Network Attack](https://github.com/Chowdery/SCADA-Profinet_Network-Attack.git) - Profinet
* [SCADA-Tools](https://github.com/atimorin/scada-tools.git) - NSE and other Scripts
* [Nmap-SCADA](https://github.com/jpalanco/nmap-scada.git) - NSE Scripts
* [Digital Bond Redpoint](https://github.com/digitalbond/Redpoint.git) - NSE Scripts
* [Industrial Exploitation Framework](https://github.com/dark-lbp/isf.git) - Multiple ICS Protocols and tools
  * This tool requires Python 2. Pipenv shell script is generated to run the tool.
* [Windows Exploit Suggester - Next Generation (WES-NG)](https://github.com/bitsadmin/wesng) - Windows Configuration

### Requirements
#### Packages
* python3-pip
* python2
* pipenv
* cmake
* git
* rustc
* vim
  
#### Python
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

### Tested On
* Ubuntu 20.04.2.0 LTS
* Kali 2020.4

## Zeek Package Install Script
### Installation
Run script: 

```zsh
chmod linux_install_ics_zeek.zsh
./linux_install_ics_zeek.zsh
```
### Parsing with Zeek
Analyze PCAP files using: 
```zsh
zeek -Cr <pcap> $HOME/Tools/ics-zeek/load.zeek
```