<#
	set_win_fw_secure_auth.ps1 - This script will configure Windows Firewall
        to protect the communications for a Modbus server and client using
        built in IPSec capabilities of the Windows OS. Secure authentication
        defaults to Machine Kerberos but can be configured for Pre-shared
        Key on systems not connected to a Windows Domain (not recommended).

    WARNING: This script will modify your system. Test before implementing.
        This script is are distributed in the hope that they will be useful, 
        but WITHOUT ANY WARRANTY; without even the implied warranty of 
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    Author: Don C. Weber (@cutaway)
    Date:   April 16, 2022
#>

<#
	License: 
	Copyright (c) 2022, Cutaway Security, Inc. <dev [@] cutawaysecurity.com>
	
	set_win_fw_secure_auth.ps1 is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	
	set_win_fw_secure_auth.ps1 is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
	Point Of Contact:    Don C. Weber <dev [@] cutawaysecurity.com>
#>

param (
    [switch] $help,
    [switch] $check,
    [switch] $disable_warning,
    [string] $mb_server    = '',
    [string] $mb_client    = '',
    [string] $mb_port      = '10502',
    [string] $dname_header = 'SANS ICS Concepts: ',
    [string] $auth_method  = 'Kerberos',
    [string] $psk          = 'controlthings.io'
)

#########################################
# Usage
#########################################
Function Get-Usage{
    Write-Output "`nServer Firewall Configuration"
    Write-Output "  NOTE: Not providing these options will configure authentication for the Modbus Client"
    Write-Output "    -mb_server <server IP address> : Modbus Server IP Address"
    Write-Output "    -mb_client <server IP address> : Modbus Server IP Address"
    Write-Output "`nOther Configuration Options"
    Write-Output "    -mb_port <server IP address> : Modbus Server Port [Default: 10502]"
    Write-Output "    -auth_method (Kerberos | PSK) : Authentication Type [Default: Kerberos]"
    Write-Output "    -dname_header 'Descriptive Name: ' : Descriptive name to tag firewall rules [Default: 'SANS ICS Concepts: ']"
    Write-Output "    -psk 'correcthorsestaplebattery' : Pre-Shared Key [Default: controlthings.io]"
    Write-Output "    -show_warning : Pre-Shared Key [Default: controlthings.io]"
    Write-Output "    -help : Displays this help message"
    Write-Output "    -check : checks for rules using the configured -dname_header`n"
    Exit
}
if($help){
    Get-Usage
}

#########################################
# Settings
#########################################
if ($auth_method -eq 'Kerberos'){
    $authp_dname = "$dname_header Proposed Machine Auth Kerberos"
    $ipsec_dname = "$dname_header Authenticate using Machine Kerberos"
}elseif ($auth_method -eq 'PSK'){
    $authp_dname = "$dname_header Proposed PSK Auth"
    $ipsec_dname = "$dname_header Authenticate using PSK"
}else{
    Write-Output "[!] Authentication method not supported.`n"
    Get-Usage
}
$fw_dname    = "$dname_header Allow Modbus Inbound Port $mb_port"
$rule_search = "$dname_header*"
$start_time_readable = Get-Date -Format "dddd MM/dd/yyyy HH:mm"
$script_name         = 'set_win_fw_secure_auth'
$script_version      = '1.0.0'

####################
# Administration Functions
####################

# Check for Administrator Role 
####################
function Get-AdminState {
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){ 
        Write-Output "[!] You do not have Administrator rights. This script will not run correctly. Exiting" 
    } else {
        Write-Output "[*] Script running with Administrator rights." 
    }
}
####################

# Confirm System Modifications
####################
Function Get-UserConfirmation {
    if ($disable_warning){
        return
    } else {
        Write-Output "*** Use At Your Own Risk!!!! Do not run on production systems without testing. ***`n"

        Write-Output "[*] Modbus Server: $mb_server"
        Write-Output "[*] Modbus Client: $mb_client"
        Write-Output "[*] Modbus Port:   $mb_port"
        Write-Output "[*] Display Header: $dname_header"
        Write-Output "[*] Authentication Method: $auth_method"
        if ($auth_method -eq "PSK") { Write-Output "[*] Pre-Shared Key: $psk" }
        Write-Output "`n"

        # Confirm client or server configuration.
        if ($mb_server -and $mb_client){
            $confirmation = Read-Host "Proceed with configuring server? [N/y]"
        }else{
            $confirmation = Read-Host "Proceed with configuring client? [N/y]"
        }

        if ($confirmation -eq 'y') {
            Write-Output "[*] User selected to continue. Good luck..."
        } else {
            Write-Output "[!] User selected to exit. Exiting..."
            Exit
        }
    }
}
####################

#########################################
# Start Script 
#########################################
Write-Output "[*] Configuring Firewall Rules for Security Authentication: $start_time_readable"

#########################################
# Check for Windows Firewall Rules 
#########################################
# Check and exit else continue
if ($check){
    Write-Host "[*] Checking for rules:"
    Get-NetIPsecPhase1AuthSet -DisplayName $rule_search
    Get-NetIPSecRule -DisplayName $rule_search
    Get-NetFirewallRule -DisplayName $rule_search
    $finish_time_readable = Get-Date -Format "dddd MM/dd/yyyy HH:mm"
    Write-Output "`n[*] Check completed successfully. $finish_time_readable`n"
    Exit
}

#########################################
# Confirm with User Before Proceeding 
#########################################
Get-AdminState
Get-UserConfirmation

# Computer Auth via Machine via Kerberos - PREFERRED METHOD But Requires Domain
if ($auth_method -eq 'Kerberos'){
    Write-Host "[*] Configuring for Kerberos authentication"
    $mkerbauthprop   = New-NetIPsecAuthProposal -Machine -Kerberos
    $p1Auth          = New-NetIPsecPhase1AuthSet -DisplayName $authp_dname -Proposal $mkerbauthprop
}else{
    # Pre-shared Key Auth - NOT PREFFERED For DEMONSTRATION ONLY
    Write-Host "[*] Configuring for Pre-Shared Key authentication"
    $pskautprop = New-NetIPsecAuthProposal -Machine -PreSharedKey $psk
    $p1Auth     = New-NetIPsecPhase1AuthSet -DisplayName $authp_dname -Proposal $pskautprop
}

# IPSec Rule for Authentication and Encryption
Write-Output "[*] Setting NetIPSecRule"
New-NetIPSecRule -DisplayName $ipsec_dname -InboundSecurity Require -OutboundSecurity Require -Phase1AuthSet $p1Auth.Name

if ($mb_server -and $mb_client){
    # Firewall Rule
    Write-Output "[*] Server system, setting NetFirewallRule."
    New-NetFirewallRule -DisplayName $fw_dname -Direction Inbound -Protocol TCP -LocalPort $mb_port -LocalAddress $modbus_server -RemoteAddress $modbus_client -Authentication Required -Action Allow
} else {
    Write-Output "[*] Client system, not setting NetFirewallRule."
}

$finish_time_readable = Get-Date -Format "dddd MM/dd/yyyy HH:mm"
Write-Output "[*] Script completed successfully. Use the following commands to remove rules. $finish_time_readable`n"
Write-Output "[*] Remove-NetFirewallRule -DisplayName `"$rule_search`""
Write-Output "[*] Remove-NetIPSecRule -DisplayName `"$rule_search`""
Write-Output "[*] Remove-NetIPsecPhase1AuthSet -DisplayName `"$rule_search`""
