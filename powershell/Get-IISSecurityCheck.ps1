##########################################################################
# Get-IISSecurityCheck
# Version 1.0.0
# Review the configuration of a Windows IIS Server and site configurations.
# 
# Author: Don C. Weber (@cutaway) - Cutaway Security, LLC
# Date:   20220502
# 
# Usage:
#     Get-IISSecurityCheck
# 
# Usage:
#     1) Start Powershell
#     2) Run '..\Get-IISSecurityCheck.ps1'
#     3) Review each output that starts with '[-]' to determine if it is a false positive.
#     4) For references and remediations check script section for links to STIG Viewer and other resources.
#
# Resources: 
#   Blog Post - Hardening IIS with PowerShell: https://www.calcomsoftware.com/automating-iis-hardening-with-powershell/
#   STIG Viewer - Microsoft IIS 10.0 Site Security Technical Implementation Guide: https://stigviewer.com/stig/microsoft_iis_10.0_site/2020-09-25/
#   Microsoft IIS 10.0 STIG Y22M01 Checklist Details: https://ncp.nist.gov/checklist/952
#   IIS Harding using PowerShell: https://github.com/zahav/powershell-iis-hardening
#
##########################################################################

Function Get-ReportTime{
    Return Get-Date -Format "dddd MM/dd/yyyy HH:mm"
}

Function Get-LocalAccountMembers{

    $gprops = @{'Group Name'='';Name='';SID=''}
    $gmems_Template = New-Object -TypeName PSObject -Property $gprops

    $groups = Get-LocalGroup

    $gcombined = $groups | ForEach-Object {
        $gmn = $_.Name
        Get-LocalGroupMember $gmn | ForEach-Object {
            $gmems = $gmems_Template.PSObject.Copy()
            $gmems.'Group Name' = $gmn
            $gmems.Name = $_.Name
            $gmems.SID = $_.SID
            $gmems
        }
    }

    $gcombined | Format-Table -Property 'Group Name',Name,SID -AutoSize | Out-String -Width 4096
}

###################
Write-Output "`n[*] Processing IIS Configuration Settings for the server:"
###################
Write-Output "###################################"

# Start Time
Write-Output "Test started at $(Get-ReportTIme)"

# Get server FQDN
$serverFQDN = "$env:computername.$env:userdnsdomain"
Write-Output "[*] Server FQDN: $serverFQDN"

# Get IIS Configuration File location
$iisConfigFile = (Get-WebConfigFile).FullName
Write-Output "[*] Server IIS configuratino file location: $iisConfigFile"

# Get IIS Version
$iisVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("C:\Windows\system32\notepad.exe").FileVersion
Write-Output "[*] Server IIS version: $iisVersion"

Write-Output "[*] For more information about each test review STIG Viewer references: https://stigviewer.com/stig/microsoft_iis_10.0_site/2020-09-25/"
Write-Output "###################################"

###################
# STIG Viewer: https://stigviewer.com/stig/microsoft_iis_10.0_site/2020-06-08/finding/V-100225
Write-Output "`n[*] Ensure Web content is on a Non-System Partition"
###################
$test = Get-Content (Join-Path -Path $Env:SystemRoot -ChildPath 'System32\inetsrv\config\applicationHost.config')
$iisPath = Join-Path -Path $Env:SystemDrive -ChildPath 'inetpub'

if (
    (Test-Path -Path (Join-Path -Path $Env:SystemDrive -ChildPath 'inetpub')) -And
    $test -Match [RegEx]::Escape((Join-Path -Path $Env:SystemDrive -ChildPath 'inetpub'))
) {
    Write-Output "[+] Web Content is on a Non-System Partition: $iisPath"
} else {
    Write-Output "[-] Web Content is NOT on a Non-System Partition: $iisPath"
}

###################
# STIG Viewer: https://stigviewer.com/stig/microsoft_iis_10.0_site/2020-09-25/finding/V-218759
Write-Output "`n[*] Ensure Directory Browsing is Set to Disable"
###################
Get-Website | Foreach-Object {
    $appName = $_.Name
    $db = (Get-WebConfigurationProperty -Filter "/system.webServer/directoryBrowse" -PSPath "IIS:\Sites\$appName" -Name "enabled").Value
    if ($db){
        Write-Output "[-] $appName Directory Browsing is NOT disabled"
    } else {
        Write-Output "[+] $appName Directory Browsing is disabled"
    }
}

###################
# STIG Viewer: https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-09-25/finding/V-218771
Write-Output "`n[*] Ensure Application pool identity is configured for all application pools"
###################
$AppPools = Get-ChildItem 'IIS:\AppPools'
$AppPools | Where-Object {!($_.Name -match '.NET')} | Foreach-Object {
    $appName = $($_.Name)
    $processModels = Get-ItemProperty "IIS:\AppPools\$appName" | Select-Object -ExpandProperty 'processModel'

    If ( $processModels.identityType -eq 'ApplicationPoolIdentity' ) {
        Write-Output "[+] $appName Application Pool identity is configured"
    } Else {
        Write-Output "[-] $appName Application Pool identity is NOT configured"
    }
}

###################
# STIG Viewer: https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-09-25/finding/V-218771
Write-Output "`n[*] Ensure unique application pools is set for sites"
###################
$websiteCnt = (Get-Website).count
$appPoolCnt = ((get-iisapppool).Name | Where-Object {!($_ -match '.NET')}).count

if ($websiteCnt -eq $appPoolCnt){
    Write-Output "[+] There are $websiteCnt Websites and $appPoolCnt Application Pools. Therefore unique applicationPool is set."
} else {
    Write-Output "[-] There are $websiteCnt Websites and $appPoolCnt Application Pools. Therefore unique application pools are NOT set."
}


###################
# STIG Viewer: https://stigviewer.com/stig/microsoft_iis_10.0_site/2021-03-24/finding/V-218750
Write-Output "`n[*] Ensure application pool identity is configured for anonymous user identity"
###################
Get-ChildItem 'IIS:\Sites' | Foreach-Object {
    $appName = $_.Name
    $anonAuth = (Get-WebConfigurationProperty -Filter '/system.webServer/security/authentication/anonymousAuthentication' -PSPath "IIS:\Sites\$appName" -Name "userName").Value

    # https://stigviewer.com/stig/microsoft_iis_10.0_site/2021-03-24/finding/V-218750
    # If the IUSR account or any account noted above used for anonymous access is a member of any group with privileged access, this is a finding.

    if ($anonAuth){
        Write-Output "[+] $appName anonymousAuthentication is set. Check if the `'$anonAuth`' account is a member of any group with privileged access, this is a finding."
    } else {
        Write-Output "[-] $appName anonymousAuthentication is NOT set"
    }
    Write-Output "`nIf the $anonAuth account or any account noted above used for anonymous access is a member of any group with privileged access, this is a finding."
    Get-LocalAccountMembers
}

###################
# STIG Viewer: https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-09-25/finding/V-218746
Write-Output "`n[*] Ensure WebDav feature is disabled"
###################
$webDavEnabled = [Bool](Get-WindowsFeature -Name 'Web-DAV-Publishing' | Where-Object Installed -EQ $true)
if ($webDavEnabled){
    Write-Output "[-] WebDav feature is NOT disabled. Confirm WebDave is required."
} else {
    Write-Output "[+] WebDav feature is disabled"
}

###################
# STIG Viewer: https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2021-03-24/finding/V-218825
Write-Output "`n[*] Ensure global authorization rule is set to restrict access"
###################
if ((Get-WindowsFeature Web-Url-Auth).Installed -EQ $true) {
    Get-WebSite | ForEach-Object {
        $appName = $_.Name
        $config = Get-WebConfiguration -Filter "system.webServer/security/authorization" -PSPath "IIS:\Sites\$($_.Name)"

        $config.GetCollection() | ForEach-Object {
            $accessType = ($_.Attributes | Where-Object Name -eq 'accessType').Value
            $users = ($_.Attributes | Where-Object Name -eq 'users').Value
            $roles = ($_.Attributes | Where-Object Name -eq 'roles').Value

            if (($accessType -EQ "Allow" -Or $accessType -EQ 0) -And ($users -eq "*" -or $roles -eq "?")){
                Write-Output "[-] $appName global authorization rule is NOT set to restrict access."
            } else {
                Write-Output "[+] $appName global authorization rule is set to restrict access"
            }
            Write-Output "[!] $appName Authorization settings: AccessType: $accessType | Users: $users | Roles: $roles"
        }
    }
}

###################
# General: Websites should require authentication, where possible.
Write-Output "`n[*] Ensure access to sensitive site features is restricted to authenticated principals only"
###################
Get-Website | Foreach-Object {
    $appName = $_.name
    $mode = (Get-WebConfiguration -Filter 'system.web/authentication' -PSPath "IIS:\sites\$($_.Name)").mode

    if (($mode -ne 'forms') -And ($mode -ne 'Windows')){
        Write-Output "[-] $appName features are NOT restricted to authenticated principals: $mode"
    } else {
        Write-Output "[+] $appName features are restricted to authenticated principals: $mode"
    }
}

###################
# General: Websites with forms require sessions management mechanisms are protected
# STIG Viewer: https://stigviewer.com/stig/microsoft_iis_10.0_site/2020-09-25/finding/V-218770
# STIG Viewer: https://stigviewer.com/stig/microsoft_iis_10.0_site/2020-09-25/finding/V-218736
Write-Output "`n[*] Ensure forms authentication requires SSL and Cookies and Cookie Protection"
###################
Get-Website | Foreach-Object {
    $appName = $_.name
    $config = (Get-WebConfiguration -Filter 'system.web/authentication' -PSPath "IIS:\sites\$appName")

    if ($config.mode -eq 'forms'){
        $sslConfig = $config.Forms.RequireSSL
        $cookieConfig = $config.Forms.Cookieless
        $cookieProtection = $config.Forms.protection
        $format = (Get-WebConfiguration -Filter '/system.web/authentication/forms/credentials' -PSPath "IIS:\sites\$site").passwordFormat
        # The IsLocallyStored parameter does not appear to be available. Maintain in case this is a new setting.
        #$stored = (Get-WebConfiguration -filter '/system.web/authentication/forms/credentials' -PSPath "IIS:\sites\$($_.Name)").IsLocallyStored

        if ($sslConfig){
            Write-Output "[+] $appName forms authentication requires SSL"
        } else {
            Write-Output "[-] $appName forms authentication does NOT require SSL"
        }
        
        if ($cookieConfig -eq 'UseCookie'){
            Write-Output "[+] $appName forms authentication set to use cookies"
        } else {
            Write-Output "[-] $appName forms authentication NOT set to use cookies"
        }
        
        if ($cookieProtection -eq 'All'){
            Write-Output "[+] $appName forms authentication set to use cookie protection"
        } else {
            Write-Output "[-] $appName forms authentication NOT set to use cookie protection"
        }
        
        if ($format -eq 'SHA1'){
            Write-Output "[+] $appName forms authentication passwordFormat set to protected: $format"
        } else {
            Write-Output "[-] $appName forms authentication passwordFormat NOT set to protected (is set clear or MD5): $format"
        }        
        <#
        # The IsLocallyStored parameter does not appear to be available. Maintain in case this is a new setting.
        if ($stored){
            # TODO: Determine what IsLocallyStored returns
            Write-Output "[+] $appName credentials IsLocallyStored set to $stored"
        } else {
            Write-Output "[-] $appName credentials IsLocallyStored not set"
        } 
        #>       
    } else {
        Write-Output "[+] $appName does not contain forms"
    }
}

###################
# General: Websites with forms require sessions management mechanisms are protected
# STIG Viewer: https://stigviewer.com/stig/microsoft_iis_10.0_site/2020-09-25/finding/V-218770
# STIG Viewer: https://stigviewer.com/stig/microsoft_iis_10.0_site/2020-09-25/finding/V-218736
Write-Output "`n[*] Ensure machine setting for passwordFormat is not set to clear"
###################
$machineConfig = [System.Configuration.ConfigurationManager]::OpenMachineConfiguration()
$passwordFormat = $machineConfig.GetSection("system.web/authentication").forms.credentials.passwordFormat

if ($passwordFormat -eq 'SHA1'){
    Write-Output "[+] Machine configuration for forms authentication passwordFormat set to protected"
} else {
    Write-Output "[-] Machine configuration for forms authentication passwordFormat NOT set to protected (is set clear or MD5)"
}

###################
# General: Basic authentication should be encrypted.
Write-Output "`n[*] Ensure transport layer security for basic authentication is configured"
###################
Get-Website | Foreach-Object {
    $ssl   = (Get-WebConfiguration -Filter "/system.webServer/security/access" -PSPath "IIS:\sites\$($_.Name)").SSLFlags
    $basic = (Get-WebConfigurationProperty -filter "/system.WebServer/security/authentication/basicAuthentication" -name Enabled -PSPath "IIS:\sites\$($_.Name)").Value

    if ($basic){
        If($ssl -eq 'Ssl'){
            Write-Output "[+] $appName features uses basic authentication with TLS: $ssl"
        } else {
            Write-Output "[-] $appName features uses basic authentication does NOT use TLS: $ssl"
        }
    } else {
        Write-Output "[+] $appName does not use basic authentication"
    }
}
        
###################
# General: Enabling retail mode configures the server to prevent displaying some error messages to end user
# Microsoft: https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.deploymentsection.retail?view=netframework-4.8
Write-Output "`n[*] Ensure machine setting for deployment method retail is set"
###################
$machineConfig = [System.Configuration.ConfigurationManager]::OpenMachineConfiguration()
$deployment = $machineConfig.GetSection("system.web/deployment")
$retail = $deployment.Retail

if ($retail){
    # TODO: Determine what IsLocallyStored returns
    Write-Output "[+] $appName machine setting for deployment method retail set to $retail"
} else {
    Write-Output "[-] $appName machine setting for deployment method retail NOT set"
} 

###################
# PowerShell IIS Hardening: https://github.com/zahav/powershell-iis-hardening
Write-Output "`n[*] Ensure debugging is turned off"
###################
Get-Website | Foreach-Object {
    $appName = $_.name
    $debug = (Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$appName" -filter "system.web/compilation" -name "debug").Value

    if ($debug){
        Write-Output "[-] $appName debugging is NOT set to False"
    } else {
        Write-Output "[+] $appName debugging is set to False"
    }      
}

###################
# PowerShell IIS Hardening: https://github.com/zahav/powershell-iis-hardening
Write-Output "`n[*] Ensure custom error messages are not off"
###################
Get-Website | Foreach-Object {
    $appName = $_.name
    $mode = (Get-WebConfiguration -Filter '/system.web/customErrors' -PSPath "IIS:\sites\$appName").Mode

    if ($mode -eq 'off'){
        Write-Output "[-] $appName custom error messages is NOT set to On or RemoteOnly: $mode"
    } else {
        Write-Output "[+] $appName custom error messages are NOT set to On or RemoteOnly: $mode"
    }      
}

###################
# PowerShell IIS Hardening: https://github.com/zahav/powershell-iis-hardening
Write-Output "`n[*] Ensure IIS HTTP detailed errors are hidden from displaying remotely"
###################
Get-Website | Foreach-Object {
    $appName = $_.name
    $errorMode = (Get-WebConfiguration -Filter '/system.webServer/httpErrors' -PSPath "IIS:\sites\$($_.Name)").errorMode

    if (($errorMode -NE 'Custom') -And ($errorMode -NE 'DetailedLocalOnly')){
        Write-Output "[-] $appName IIS HTTP detailed errors set to $errorMode and are NOT hidden from displaying remotely"
    } else {
        Write-Output "[+] $appName IIS HTTP detailed errors set to $errorMode and are hidden from displaying remotely"
    } 
}

###################
# PowerShell IIS Hardening: https://github.com/zahav/powershell-iis-hardening
Write-Output "`n[*] Ensure ASP.NET stack tracing is not enabled"
###################
# Individual Site Config
Get-Website | Foreach-Object {
    $appName = $_.name
    $tracing = (Get-WebConfiguration -Filter '/system.web/trace' -PSPath "IIS:\sites\$appName").enabled

    if (!($tracing)){
        Write-Output "[+] $appName ASP.NET stack tracing is disabled"
    } else {
        Write-Output "[-] $appName ASP.NET stack tracing is NOT disabled"
    } 
}

# Machine Config
$machineConfig = [System.Configuration.ConfigurationManager]::OpenMachineConfiguration()
$deployment = $machineConfig.GetSection("system.web/trace")
if ($deployment.enabled){
    Write-Output "[-] Machine configuration for ASP.NET stack tracing is NOT disabled"
} else {
    Write-Output "[+] Machine configuration for ASP.NET stack tracing is disabled"
} 

###################
# STIG Viewer: https://stigviewer.com/stig/microsoft_iis_10.0_site/2020-09-25/finding/V-218736
# PowerShell IIS Hardening: https://github.com/zahav/powershell-iis-hardening
Write-Output "`n[*] Ensure httpcookie mode is configured for session state"
###################
Get-Website | Foreach-Object {
    $appName = $_.Name
    $sessionMode = (Get-WebConfiguration -Filter '/system.web/sessionState' -PSPath "IIS:\sites\$appName").mode

    if ($sessionMode -eq 'StateServer'){
        Write-Output "[+] $appName session Mode is set for StateServer: $sessionMode"
    } else {
        Write-Output "[-] $appName session Mode is NOT set for StateServer: $sessionMode"
    }

    $sessionState = (Get-WebConfiguration -Filter '/system.web/sessionState' -PSPath "IIS:\sites\$appName").cookieless
    $cookieLess = $(if(($sessionState -eq "UseCookies") -or ($sessionState -eq "False")) { $false } Else { $true })
    if ($cookieLess){
        Write-Output "[-] $appName Sessions are configured as cookieless: $sessionState"
    } else {
        Write-Output "[+] $appName Sessions are configured to use cookies: $sessionState"
        $httpCookies = (Get-WebConfiguration -Filter '/system.web/httpCookies' -PSPath "IIS:\sites\$appName").httpOnlyCookies
        if ($httpCookies){
            Write-Output "[+] $appName httpOnlyCookies is enabled:"
        } else {
            Write-Output "[-] $appName httpOnlyCookies is NOT enabled"
        }
    }
}

###################
# STIG Viewer: https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2021-03-24/finding/V-218807
Write-Output "`n[*] Ensure Site MachineKey validation method - .Net 4.5 is configured"
###################
Get-Website | Foreach-Object {
    $appName = $_.name

    $siteKeyValidation = (Get-WebConfiguration -filter "system.web/machineKey" -PSPath "IIS:\sites\$appName").validation
    $siteKeyDecryption = (Get-WebConfiguration -filter "system.web/machineKey" -PSPath "IIS:\sites\$appName").decryption

    if ($siteKeyValidation -eq 'AES'){
        Write-Output "[+] $appName MachinKey Validation set to AES."
    } else {
        Write-Output "[-] $appName MachinKey Validation NOT set to AES: $siteKeyValidation"
    }

    if ($siteKeyDecryption -eq 'Auto'){
        Write-Output "[+] $appName MachineKey Encryption set to Auto"
    } else {
        Write-Output "[-] $appName MachineKey Encryption NOT set to Auto: $siteKeyDecryption"
    }
}

###################
# STIG Viewer: https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2021-03-24/finding/V-218807
Write-Output "`n[*] Ensure IIS MachineKey validation method - .Net 4.5 is configured"
###################
$machineKeyValidation = (Get-WebConfiguration -filter "system.web/machineKey").validation
$machineKeyDecryption = (Get-WebConfiguration -filter "system.web/machineKey").decryption

if ($siteKeyValidation -eq 'AES'){
    Write-Output "[+] IIS MachinKey Validation set to AES."
} else {
    Write-Output "[-] IIS MachinKey Validation NOT set to AES: $siteKeyValidation"
}

if ($siteKeyDecryption -eq 'Auto'){
    Write-Output "[+] IIS MachineKey Encryption set to Auto"
} else {
    Write-Output "[-] IIS MachineKey Encryption NOT set to Auto: $siteKeyDecryption"
}

###################
# STIG Viewer: https://www.stigviewer.com/stig/iis_8.5_site/2018-04-06/finding/V-76805
# PowerShell IIS Hardening: https://github.com/zahav/powershell-iis-hardening
Write-Output "`n[*] Ensure site global .NET trust level setting is configured"
###################
Get-Website | Foreach-Object {
    $appName = $_.name

    $level = (Get-WebConfiguration -filter "system.web/trust" -PSPath "IIS:\sites\$appName" | Select-Object -Property *).level
    if (($level -eq 'Full') -or ($level -eq 'High')){
        Write-Output "[-] $appName Trust Level NOT set to Medium or lower: $level"
    } else {
        Write-Output "[+] $appName Trust Level set to Medium or lower: $level"
    }
}

###################
# STIG Viewer: https://www.stigviewer.com/stig/iis_8.5_site/2018-04-06/finding/V-76805
# PowerShell IIS Hardening: https://github.com/zahav/powershell-iis-hardening
Write-Output "`n[*] Ensure IIS global .NET trust level setting is configured"
###################
$level = (Get-WebConfiguration -filter "system.web/trust" -PSPath "IIS:\sites\$appName" | Select-Object -Property *).level
if (($level -eq 'Full') -or ($level -eq 'High')){
    Write-Output "[-] IIS Trust Level NOT set to Medium or lower: $level"
} else {
    Write-Output "[+] IIS Trust Level set to Medium or lower: $level"
}

###################
# PowerShell IIS Hardening: https://github.com/zahav/powershell-iis-hardening
Write-Output "`n[*] Ensure X-Powered-By Header and Server Headers are removed"
###################
Get-Website | Foreach-Object {
    $appName = $_.Name
    $config = Get-WebConfiguration -Filter '/system.webServer/httpProtocol/customHeaders' -PSPath "IIS:\sites\$appName"

    $customHeaders = $config.GetCollection()

    if ($customHeaders) {
        $customHeaders | ForEach-Object {
            $xpoweredby = ($_.Attributes | Where-Object Name -EQ name).Value -match 'x-powered-by'
            if ($xpoweredby){
                Write-Output "[-] $appName X-Powered-By Header is NOT disabled"
            } else {
                Write-Output "[+] $appName X-Powered-By Header is disabled"
            }
            $serverheader = ($_.Attributes | Where-Object Name -EQ name).Value -match 'server'
            if ($serverheader){
                Write-Output "[-] $appName Server Header is NOT disabled"
            } else {
                Write-Output "[+] $appName Server Header is disabled"
            }
        }
    } else {
        Write-Output "[+] $appName no custom headers"
    }
}

###################
# PowerShell IIS Hardening: https://github.com/zahav/powershell-iis-hardening
Write-Output "`n[*] Ensure Request Filterings are configured"
###################
If ((Get-WindowsFeature Web-Filtering).Installed -EQ $true) {
    Get-Website | Foreach-Object {
        $appName = $_.Name
        # Should be 30,000,000 or less
        $maxAllowedContentLength = (((Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "IIS:\sites\$appName").requestLimits).Attributes | Where-Object Name -EQ 'maxAllowedContentLength').Value
        if ($maxAllowedContentLength){
            if ($maxAllowedContentLength -le 30000000){
                Write-Output "[+] $appName maxAllowedContentLength is okay, set to $maxAllowedContentLength"
            } else {
                Write-Output "[-] $appName maxAllowedContentLength is NOT okay, set to $maxAllowedContentLength"
            }
        } else {
            Write-Output "[-] $appName maxAllowedContentLength is NOT enabled"
        }
        
        # Should be 4096 or less
        $maxURL = (((Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "IIS:\sites\$appName").requestLimits).Attributes | Where-Object Name -EQ 'maxURL').Value
        if ($maxURL){
            if ($maxURL -le 4096){
                Write-Output "[+] $appName maxURL is okay, set to $maxURL"
            } else {
                Write-Output "[-] $appName maxURL is NOT okay, set to $maxURL"
            }
        } else {
            Write-Output "[-] $appName maxURL is NOT enabled"
        }
        
        # Should be 2048 or less
        $maxQueryString = (((Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "IIS:\sites\$appName").requestLimits).Attributes | Where-Object Name -EQ 'maxQueryString').Value
        if ($maxQueryString){
            if ($maxQueryString -le 2048){
                Write-Output "[+] $appName maxQueryString is okay, set to $maxQueryString"
            } else {
                Write-Output "[-] $appName maxQueryString is NOT okay, set to $maxQueryString"
            }
        } else {
            Write-Output "[-] $appName maxQueryString is NOT enabled"
        }
        
        # should be false
        $allowHighBitCharacters = (Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "IIS:\sites\$appName").allowHighBitCharacters
        if ($allowHighBitCharacters -ne $null){
            if ($allowHighBitCharacters){
                Write-Output "[-] $appName allowHighBitCharacters is NOT okay, set to $allowHighBitCharacters"
            } else {
                Write-Output "[+] $appName allowHighBitCharacters is okay, set to $allowHighBitCharacters"
            }
        } else {
            Write-Output "[-] $appName allowHighBitCharacters is NOT enabled"
        }
        
        # should be false
        $allowDoubleEscaping = (Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "IIS:\sites\$appName").allowDoubleEscaping
        if ($allowDoubleEscaping -ne $null){
            if ($allowDoubleEscaping){
                Write-Output "[-] $appName allowDoubleEscaping is NOT okay, set to $allowDoubleEscaping"
            } else {
                Write-Output "[+] $appName allowDoubleEscaping is okay, set to $allowDoubleEscaping"
            }
        } else {
            Write-Output "[-] $appName allowDoubleEscaping is NOT enabled"
        }
        
        # should be false
        $allowUnlisted = (((Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "IIS:\sites\$appName").fileExtensions).Attributes | Where-Object Name -EQ 'allowUnlisted').Value
        if ($allowUnlisted -ne $null){
            if ($allowUnlisted){
                Write-Output "[-] $appName allowUnlisted is NOT okay, set to $allowUnlisted"
            } else {
                Write-Output "[+] $appName allowUnlisted is okay, set to $allowUnlisted"
            }
        } else {
            Write-Output "[-] $appName allowUnlisted is NOT enabled"
        }
    }
}

###################
# PowerShell IIS Hardening: https://github.com/zahav/powershell-iis-hardening
Write-Output "`n[*] Ensure HTTP Trace Method is disabled"
###################
If ((Get-WindowsFeature Web-Filtering).Installed -EQ $true) {
    Get-Website | Foreach-Object {
        $site = $_
        $appName = $site.name

        $config = (Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath "IIS:\sites\$appName")
        $trace = $false
        $config.verbs.Attributes | Where-Object {
            if ($_.Name -eq 'trace'){ $trace = $true }
        }
        if ($trace){
            Write-Output "[-] $appName HTTP Trace Method is NOT disabled"
        } else {
            Write-Output "[+] $appName HTTP Trace Method is disabled"
        }
    }
}

###################
# PowerShell IIS Hardening: https://github.com/zahav/powershell-iis-hardening
# Microsoft IIS Handlers: https://docs.microsoft.com/en-us/iis/configuration/system.webserver/handlers/
Write-Output "`n[*] Ensure Site Handler is not granted Write and Script/Execute"
###################
Get-Website | Foreach-Object {
    $appName = $_.Name

    $granted = (Get-WebConfiguration -Filter 'system.webServer/handlers' -PSPath "IIS:\sites\$appName").accessPolicy

    # TODO: What should this be?
    if ($granted -eq 'Read/Script'){
        Write-Output "[+] $appName Handler set for Read/Script: $granted"
    } else {
        Write-Output "[-] $appName Handler NOT set for Read/Script: $granted"
    }
}

###################
# PowerShell IIS Hardening: https://github.com/zahav/powershell-iis-hardening
# Microsoft IIS Handlers: https://docs.microsoft.com/en-us/iis/configuration/system.webserver/handlers/
Write-Output "`n[*] Ensure IIS Handler is not granted Write and Script/Execute"
###################
$appName = $_.Name

$granted = (Get-WebConfiguration -Filter 'system.webServer/handlers').accessPolicy

# TODO: What should this be?
if ($granted -eq 'Read/Script'){
    Write-Output "[+] IIS Handler set for Read/Script: $granted"
} else {
    Write-Output "[-] IIS Handler NOT set for Read/Script: $granted"
}

###################
# PowerShell IIS Hardening: https://github.com/zahav/powershell-iis-hardening
Write-Output "`n[*] Ensure site configurations for notListedIsapisAllowed and notListedCgisAllowed are set to false"
###################
Get-Website | Foreach-Object {
    $appName = $_.Name
    $isapisAllowed = (Get-WebConfiguration -Filter 'system.webServer/security/isapiCgiRestriction' -PSPath "IIS:\sites\$appName").notListedIsapisAllowed
    $cgisAllowed = (Get-WebConfiguration -Filter 'system.webServer/security/isapiCgiRestriction' -PSPath "IIS:\sites\$appName").notListedCgisAllowed

    if ($isapisAllowed){
        Write-Output "[-] $appName notListedIsapisAllowed is NOT disabled"
    } else {
        Write-Output "[+] $appName  notListedIsapisAllowed is disabled"
    }

    if ($cgisAllowed){
        Write-Output "[-] $appName notListedCgisAllowed is NOT disabled"
    } else {
        Write-Output "[+] $appName  notListedCgisAllowed is disabled"
    }
}

###################
# PowerShell IIS Hardening: https://github.com/zahav/powershell-iis-hardening
Write-Output "`n[*] Ensure IIS configurations for notListedIsapisAllowed and notListedCgisAllowed are set to false"
###################
$isapisAllowed = (Get-WebConfiguration -Filter 'system.webServer/security/isapiCgiRestriction').notListedIsapisAllowed
$cgisAllowed = (Get-WebConfiguration -Filter 'system.webServer/security/isapiCgiRestriction').notListedCgisAllowed

if ($isapisAllowed){
    Write-Output "[-] IIS notListedIsapisAllowed is NOT disabled"
} else {
    Write-Output "[+] IIS notListedIsapisAllowed is disabled"
}

if ($cgisAllowed){
    Write-Output "[-] IIS notListedCgisAllowed is NOT disabled"
} else {
    Write-Output "[+] IIS notListedCgisAllowed is disabled"
}

###################
# PowerShell IIS Hardening: https://github.com/zahav/powershell-iis-hardening
Write-Output "`n[*] Ensure Dynamic IP Address Restrictions is enabled"
###################
If ((Get-WindowsFeature Web-Ip-Security).Installed -EQ $true) {
    Get-Website | Foreach-Object {
        $appName = $_.Name
        $config = Get-WebConfiguration -Filter '/system.webServer/security/dynamicIpSecurity' -PSPath "IIS:\sites\$appName"

        $denyByConcurrentRequests = $config.denyByConcurrentRequests.enabled
        $denyByRequestRate = $config.denyByRequestRate.enabled

        if ($denyByConcurrentRequests){
            Write-Output "[+] $appName Dynamic IP Address Restrictions denyByConcurrentRequests is enabled."
        } else {
            Write-Output "[-] $appName Dynamic IP Address Restrictions denyByConcurrentRequests is NOT enabled"
        }

        if ($denyByRequestRate){
            Write-Output "[+] $appName Dynamic IP Address Restrictions denyByRequestRate is enabled"
        } else {
            Write-Output "[-] $appName Dynamic IP Address Restrictions denyByRequestRate is NOT enabled"
        }
    }
}

###################
# STIG Viewer: https://stigviewer.com/stig/microsoft_iis_10.0_site/2020-09-25/finding/V-218765
# PowerShell IIS Hardening: https://github.com/zahav/powershell-iis-hardening
Write-Output "`n[*] Ensure Site weblog configuration"
###################
Get-Website | Foreach-Object {
    $appName = $_.Name
    $appLogSetting = (Get-WebConfiguration -Filter system.webServer/httpLogging -PSPath "IIS:\Sites\$appName").dontLog 
    $appSelectiveSetting  = (Get-WebConfiguration -Filter system.webServer/httpLogging -PSPath "IIS:\Sites\$appName").selectiveLogging
    $logDir = $_.logFile.Directory
    $etwLogging = $_.logFile.logTargetW3C

    if (!($appLogSetting)){
        Write-Output "[+] $appName weblog is enabled"
    } else {
        Write-Output "[-] $appName weblog is NOT enabled"
    }

    if ($appSelectiveSetting -eq 'LogAll'){
        Write-Output "[+] $appName weblog selectiveLogging is set to LogAll"
    } else {
        Write-Output "[-] $appName weblog selectiveLogging is NOT set to LogAll"
    }
    
    if (!($logDir)){
        Write-Output "[-] $appName weblog location is set to: $logDir"
    } else {
        Write-Output "[+] $appName weblog location is set to: $logDir"
    }
    if ($etwLogging -eq 'File,ETW'){
        Write-Output "[+] $appName ETW Logging Set to is set to 'File,ETW'"
    } else {
        Write-Output "[-] $appName ETW Logging Set to is NOT set to 'File,ETW'"
    }
}

###################
# STIG Viewer: https://stigviewer.com/stig/microsoft_iis_10.0_site/2020-09-25/finding/V-218765
# PowerShell IIS Hardening: https://github.com/zahav/powershell-iis-hardening
Write-Output "`n[*] Ensure Default IIS weblog configuration"
###################
$appLogSetting = (Get-WebConfiguration -Filter system.webServer/httpLogging).dontLog 
$appSelectiveSetting  = (Get-WebConfiguration -Filter system.webServer/httpLogging).selectiveLogging
$logDir = (Get-WebConfiguration -Filter "system.applicationHost/sites/siteDefaults/logFile").directory
$etwLogging = (Get-WebConfiguration -Filter "system.applicationHost/sites/siteDefaults/logFile").logTargetW3C

if (!($appLogSetting)){
    Write-Output "[+] IIS weblog is enabled"
} else {
    Write-Output "[-] IIS weblog is NOT enabled"
}

if ($appSelectiveSetting -eq 'LogAll'){
    Write-Output "[+] IIS weblog selectiveLogging is set to LogAll"
} else {
    Write-Output "[-] IIS weblog selectiveLogging is NOT set to LogAll"
}

if (!($logDir)){
    Write-Output "[-] IIS weblog location is NOT set: $logDir"
} else {
    Write-Output "[+] IIS weblog location is set to: $logDir"
}
if ($etwLogging -eq 'File,ETW'){
    Write-Output "[+] ETW Logging Set to is set to `'File,ETW`'"
} else {
    Write-Output "[-] ETW Logging Set to is NOT set to `'File,ETW`': $etwLogging"
}

###################
# STIG Viewer: https://www.stigviewer.com/stig/microsoft_windows_server_2019/2020-10-26/finding/V-205853
# PowerShell IIS Hardening: https://github.com/zahav/powershell-iis-hardening
Write-Output "`n[*] Check FTP configurations"
###################
Get-Website | Foreach-Object {
    $appName = $_.Name
    $FTPBindings = $site.bindings.collection | Where-Object -Property 'Protocol' -eq FTP
    If ($FTPBindings) {
        Write-Output "`n[*] Ensure FTP requests are encrypted"
        # TODO: What should these settings be
        $config = (Get-WebConfiguration -Filter 'system.applicationHost/sites' -PSPath "IIS:\sites\$appName").siteDefaults.ftpServer.security.ssl

        ($config.Attributes | Where-Object Name -EQ 'controlChannelPolicy').Value
        ($config.Attributes | Where-Object Name -EQ 'dataChannelPolicy').Value


        Write-Output "`n[*] Ensure FTP Logon attempt restrictions is enabled"
        $config = (Get-WebConfiguration -Filter 'system.ftpServer/security/authentication' -PSPath "IIS:\sites\$appName").denyByFailure
        [PSCustomObject]@{
            "Site"        = $site.Name
            "Enabled"     = $config.enabled
            "MaxFailures" = $config.maxFailure
            "EntryExp"    = ($config.entryExpiration).ToString()
            "Logging"     = $config.loggingOnlyMode
        }

    } else {
        Write-Output "[+] $appName  FTP server is disabled"
    }
}

###################
# STIG Viewer: https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2021-06-23/finding/V-218827
# Microsoft HSTS Settings for a Website: https://docs.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/site/hsts
Write-Output "`n[*] Ensure HSTS Header is set"
###################
Get-Website | Foreach-Object {
    $appName = $_.Name
    $sitesCollection = Get-IISConfigSection -SectionPath "system.applicationHost/sites" | Get-IISConfigCollection
    $siteElement = Get-IISConfigCollectionElement -ConfigCollection $sitesCollection -ConfigAttribute @{"name"=$appName}
    $hstsElement = Get-IISConfigElement -ConfigElement $siteElement -ChildElementName "hsts"

    $enabled = ($hstsElement.Attributes | Where-Object {$_.Name -eq 'enabled'}).Value
    $maxage = ($hstsElement.Attributes | Where-Object {$_.Name -eq 'max-age'}).Value
    $includeSubDomains = ($hstsElement.Attributes | Where-Object {$_.Name -eq 'includeSubDomains'}).Value
    $redirectHttpToHttps = ($hstsElement.Attributes | Where-Object {$_.Name -eq 'redirectHttpToHttps'}).Value

    if ($enabled){
        Write-Output "[+] $appName HSTS Header is set"
    } else {
        Write-Output "[-] $appName HSTS Header is NOT set"
    }
    if ($maxage > 0){
        Write-Output "[+] $appName HSTS Header max-age is set: $max-age"
    } else {
        Write-Output "[-] $appName HSTS Header is NOT set"
    }
    if ($includeSubDomains){
        Write-Output "[+] $appName HSTS Header includeSubDomains is set"
    } else {
        Write-Output "[-] $appName HSTS Header includeSubDomains is NOT set"
    }
    if ($redirectHttpToHttps){
        Write-Output "[+] $appName HSTS Header redirectHttpToHttps is set"
    } else {
        Write-Output "[-] $appName HSTS Header redirectHttpToHttps is NOT set"
    }
}

###################
# STIG Viewer: https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2021-03-24/finding/V-218821
Write-Output "`n[*] Ensure SSLv2 is Disabled"
###################
$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0"

If ((Test-Path -Path $path) -and (Test-Path -Path "$path\Server")) {
    $Key = Get-Item "$path\Server"

    if ($null -ne $Key.GetValue("Enabled", $null)) {
        $value = Get-ItemProperty "$path\Server" | Select-Object -ExpandProperty "Enabled"
        # Ensure it is set to 1
        if ($value -eq 0) {
            Write-Output "[-] SSLv2 is NOT disabled"
        } Else {
            Write-Output "[+] SSLv2 is disabled"
        }
    }
} else {
    Write-Output "[-] $path keys not found, therefore SSLv2 is NOT disabled"
}

###################
# STIG Viewer: https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2021-03-24/finding/V-218821
Write-Output "`n[*] Ensure SSLv3 is Disabled"
###################
$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0"

If ((Test-Path -Path $path) -and (Test-Path -Path "$path\Server")) {
    $Key = Get-Item "$path\Server"

    if ($null -ne $Key.GetValue("Enabled", $null)) {
        $value = Get-ItemProperty "$path\Server" | Select-Object -ExpandProperty "Enabled"
        # Ensure it is set to 1
        if ($value -eq 0) {
            Write-Output "[-] SSLv3 is NOT disabled"
        } Else {
            Write-Output "[+] SSLv3 is disabled"
        }
    }
} else {
    Write-Output "[-] $path keys not found, therefore SSLv3 is NOT disabled"
}

###################
# STIG Viewer: https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2021-03-24/finding/V-218821
Write-Output "`n[*] Ensure TLS 1.0 is Disabled"
###################
$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"

If ((Test-Path -Path $path)) {
    $Key = Get-Item "$path"

    if ($null -ne $Key.GetValue("Enabled", $null)) {
        $value = Get-ItemProperty "$path\Server" | Select-Object -ExpandProperty "Enabled"
        # Ensure it is set to 1
        if ($value -eq 0) {
            Write-Output "[-] TLSv1 is NOT disabled"
        } Else {
            Write-Output "[+] TLSv1 is disabled"
        }
    }
} else {
    Write-Output "[-] $path keys not found, therefore TLSv1.0 is NOT disabled"
}

###################
# STIG Viewer: https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2021-03-24/finding/V-218821
Write-Output "`n[*] Ensure TLS 1.1 is Disabled"
###################
$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"

If ((Test-Path -Path $path)) {
    $Key = Get-Item "$path"

    if ($null -ne $Key.GetValue("Enabled", $null)) {
        $value = Get-ItemProperty "$path\Server" | Select-Object -ExpandProperty "Enabled"
        # Ensure it is set to 1
        if ($value -eq 0) {
            Write-Output "[-] TLSv1.1 is NOT disabled"
        } Else {
            Write-Output "[+] TLSv1.1 is disabled"
        }
    }
} else {
    Write-Output "[-] $path keys not found, therefore TLSv1.1 is NOT disabled"
}


###################
Write-Output "`n###################################"
Write-Output "[*] Testing completed."
Write-Output "`nTest started at $(Get-ReportTIme)"
Write-Output "###################################"
###################