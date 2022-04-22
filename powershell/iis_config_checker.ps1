

# Resource: https://www.calcomsoftware.com/automating-iis-hardening-with-powershell/

###################
Write-Output "`n[*] Ensure Web content is on a Non-System Partition"
###################
$test = Get-Content (Join-Path -Path $Env:SystemRoot -ChildPath 'System32\inetsrv\config\applicationHost.config')

if (
    (Test-Path -Path (Join-Path -Path $Env:SystemDrive -ChildPath 'inetpub')) -And
    $test -Match [RegEx]::Escape((Join-Path -Path $Env:SystemDrive -ChildPath 'inetpub'))
) {
    Write-Output "[+] Web Content is on a Non-System Partition"
} else {
    Write-Output "[-] Web Content is NOT on a Non-System Partition"
}

###################
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
Write-Output "`n[*] Ensure Application pool identity is configured for all application pools"
###################
$AppPools = Get-ChildItem 'IIS:\AppPools'
$AppPools | Foreach-Object {
    $appName = $($_.Name)
    $processModels = Get-ItemProperty "IIS:\AppPools\$appName" | Select-Object -ExpandProperty 'processModel'

    If ( $processModels.identityType -eq 'ApplicationPoolIdentity' ) {
        Write-Output "[+] $appName Application Pool identity is configured"
    } Else {
        Write-Output "[-]  $appName Application Pool identity is NOT configured"
    }
}

###################
Write-Output "`n[*] Ensure unique application pools is set for sites"
###################
$uniqAppPool = [Bool](Get-WebApplication | Group-Object -Property 'applicationPool' | Where-Object 'count' -GT 1)
if ($uniqAppPool){
    Write-Output "[+] $appName unique applicationPool is set"
} else {
    Write-Output "[-] $appName unique applicationPool is NOT set"
}


###################
Write-Output "`n[*] Ensure ‘application pool identity’ is configured for anonymous user identity"
###################
Get-ChildItem 'IIS:\Sites' | Foreach-Object {
    $appName = $_.Name
    $anonAuth = (Get-WebConfigurationProperty -Filter '/system.webServer/security/authentication/anonymousAuthentication' -PSPath "IIS:\Sites\$appName" -Name "userName").Value

    # https://stigviewer.com/stig/microsoft_iis_10.0_site/2021-03-24/finding/V-218750
    # If the IUSR account or any account noted above used for anonymous access is a member of any group with privileged access, this is a finding.

    if ($anonAuth){
        Write-Output "[+] $appName anonymousAuthentication is set. Check if the $anonAuth account is a member of any group with privileged access, this is a finding."
    } else {
        Write-Output "[-] $appName anonymousAuthentication is NOT set"
    }
}

###################
Write-Output "`n[*] Ensure WebDav feature is disabled"
###################
$webDavEnabled = [Bool](Get-WindowsFeature -Name 'Web-DAV-Publishing' | Where-Object Installed -EQ $true)
if ($webDavEnabled){
    Write-Output "[-] WebDav feature is Enabled"
} else {
    Write-Output "[+] WebDav feature is Disabled"
}

###################
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
Write-Output "`n[*] Ensure access to sensitive site features is restricted to authenticated principals only"
###################
Get-Website | Foreach-Object {
    $appName = $_.name
    $mode = (Get-WebConfiguration -Filter 'system.web/authentication' -PSPath "IIS:\sites\$($_.Name)").mode

    if (($mode -ne 'forms') -And ($mode -ne 'Windows')){
        Write-Output "[-] $appName features are NOT restricted to authenticated principals"
    } else {
        Write-Output "[+] $appName features are restricted to authenticated principals"
    }
}

###################
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
        $stored = (Get-WebConfiguration -filter '/system.web/authentication/forms/credentials' -PSPath "IIS:\sites\$($_.Name)").IsLocallyStored

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
        
        if ($format -ne 'clear'){
            Write-Output "[+] $appName forms authentication passwordFormat set to protected"
        } else {
            Write-Output "[-] $appName forms authentication passwordFormat NOT set to protected (is set clear)"
        }        
        
        if ($stored){
            # TODO: Determine what IsLocallyStored returns
            Write-Output "[+] $appName credentials IsLocallyStored set to $stored"
        } else {
            Write-Output "[!] $appName credentials IsLocallyStored not set"
        }        
    } else {
        Write-Output "[+] $appName does not contain forms"
    }
}

###################
Write-Output "`n[*] Ensure transport layer security for basic authentication is configured"
###################
Get-Website | Foreach-Object {
    $ssl   = (Get-WebConfiguration -Filter "/system.webServer/security/access" -PSPath "IIS:\sites\$($_.Name)").SSLFlags
    $basic = (Get-WebConfigurationProperty -filter "/system.WebServer/security/authentication/basicAuthentication" -name Enabled -PSPath "IIS:\sites\$($_.Name)").Value

    if ($basic){
        If($ssl -eq 'Ssl'){
            Write-Output "[+] $appName features uses basic authentication with TLS"
        } else {
            Write-Output "[+] $appName features uses basic authentication does NOT use TLS"
        }
    } else {
        Write-Output "[+] $appName does not use basic authentication"
    }
}

###################
Write-Output "`n[*] Ensure machine setting for ‘passwordFormat’ is not set to clear"
###################
$machineConfig = [System.Configuration.ConfigurationManager]::OpenMachineConfiguration()
$passwordFormat = $machineConfig.GetSection("system.web/authentication").forms.credentials.passwordFormat

if ($passwordFormat -ne 'clear'){
    Write-Output "[+] Machine configuration for forms authentication passwordFormat set to protected"
} else {
    Write-Output "[-] Machine configuration for forms authentication passwordFormat NOT set to protected (is set clear)"
}        

###################
Write-Output "`n[*] Ensure machine setting for deployment method retail is set"
###################
$machineConfig = [System.Configuration.ConfigurationManager]::OpenMachineConfiguration()
$deployment = $machineConfig.GetSection("system.web/deployment")
$retail = $deployment.Retail

if ($retail){
    # TODO: Determine what IsLocallyStored returns
    Write-Output "[+] $appName machine setting for deployment method retail set to $retail"
} else {
    Write-Output "[!] $appName machine setting for deployment method retail not set"
} 

###################
Write-Output "`n[*] Ensure custom error messages are not off"
###################
Get-Website | Foreach-Object {
    $appName = $_.name
    $mode = (Get-WebConfiguration -Filter '/system.web/customErrors' -PSPath "IIS:\sites\$appName").Mode

    if ($mode -eq 'off'){
        Write-Output "[+] $appName custom error messages are set to off"
    } else {
        Write-Output "[-] $appName custom error messages are NOT set to off"
    }      
}

###################
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
Write-Output "`n[*] Ensure ASP.NET stack tracing is not enabled"
###################
# Individual Site Config
Get-Website | Foreach-Object {
    $appName = $_.name

    if ((Get-WebConfiguration -Filter '/system.web/trace' -PSPath "IIS:\sites\$appName").enabled){
        Write-Output "[-] $appName ASP.NET stack tracing is NOT disabled"
    } else {
        Write-Output "[+] $appName ASP.NET stack tracing is disabled"
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
Write-Output "`n[*] Ensure ‘httpcookie’ mode is configured for session state"
###################
Get-Website | Foreach-Object {
    $appName = $_.Name
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
Write-Output "`n[*] Ensure 'MachineKey validation method - .Net 3.5' is configured"
###################
# TODO: What should these settings be
Get-Website | Foreach-Object {
    $appName = $_.Name
    $applicationPool = $_.applicationPool
    If ($applicationPool) {
        $pools = Get-WebApplication -Site $appName

        $pools | ForEach-Object {
            $appPool    = ($_.Attributes | Where-Object Name -EQ 'applicationPool').Value
            $properties = Get-ItemProperty -Path "IIS:\AppPools\$appPool" | Select-Object *
            $version    = $properties.managedRuntimeVersion

            If ($version -Like "v2.*") {
                $validation = (Get-WebConfiguration -Filter '/system.web/machineKey' -PSPath "IIS:\sites\$appName").Validation

                [PSCustomObject]@{
                    "Site"       = $appName
                    "AppPool"    = $appPool
                    "Version"    = $properties.managedRuntimeVersion
                    "Validation" = $validation
                }
            }
        }
    }
}

###################
Write-Output "`n[*] Ensure ‘MachineKey validation method - .Net 4.5’ is configured"
###################
# TODO: What should these settings be
Get-Website | Foreach-Object {
    $appName = $_.Name
    $applicationPool = $_.applicationPool
    If ($applicationPool) {
        $pools = Get-WebApplication -Site $appName

        $pools | ForEach-Object {
            $appPool    = ($_.Attributes | Where-Object Name -EQ 'applicationPool').Value
            $properties = Get-ItemProperty -Path "IIS:\AppPools\$appPool" | Select-Object *
            $version    = $properties.managedRuntimeVersion

            If ($version -Like "v4.*") {
                $validation = (Get-WebConfiguration -Filter '/system.web/machineKey' -PSPath "IIS:\sites\$appName").Validation

                [PSCustomObject]@{
                    "Site"       = $appName
                    "AppPool"    = $appPool
                    "Version"    = $version
                    "Validation" = $validation
                }
            }
        }
    }
}

###################
Write-Output "`n[*] Ensure global .NET trust level is configured"
###################
# TODO: What should these settings be
Get-Website | Foreach-Object {
    $appName = $_.Name
    $applicationPool = $_.applicationPool
    If ($applicationPool) {
        $pools = Get-WebApplication -Site $appName

        $pools | ForEach-Object {
            $appPool    = ($_.Attributes | Where-Object Name -EQ 'applicationPool').Value
            $properties = Get-ItemProperty -Path "IIS:\AppPools\$appPool" | Select-Object *
            $version    = $properties.managedRuntimeVersion

            $level = (Get-WebConfiguration -Filter '/system.web/trust' -PSPath "IIS:\sites\$appName").level

            [PSCustomObject]@{
                "Site"    = $appName
                "AppPool" = $appPool
                "Version" = $version
                "Level"   = $Level
            }
        }
    }
}

###################
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
Write-Output "`n[*] Ensure ‘HTTP Trace Method’ is disabled"
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
Write-Output "`n[*] Ensure Handler is not granted Write and Script/Execute"
###################
Get-Website | Foreach-Object {
    $appName = $_.Name

    $granted = (Get-WebConfiguration -Filter 'system.webServer/handlers' -PSPath "IIS:\sites\$($site.Name)").accessPolicy

    # TODO: What should this be?
    if (($granted -match 'Write') -or ($granted -match 'Execute')){
        Write-Output "[-] $appName Handler setting for Write and Script/Execute is set to: $granted"
    } else {
        Write-Output "[+] $appName Handler setting for Write and Script/Execute is set to: $granted"

    }
}

###################
Write-Output "`n[*] Ensure ‘notListedIsapisAllowed’ and ‘notListedCgisAllowed’ are set to false"
###################
Get-Website | Foreach-Object {
    $appName = $_.Name

    if ((Get-WebConfiguration -Filter 'system.webServer/security/isapiCgiRestriction' -PSPath "IIS:\sites\$appName").notListedIsapisAllowed){
        Write-Output "[-] $appName notListedIsapisAllowed is NOT disabled"
    } else {
        Write-Output "[+] $appName  notListedIsapisAllowed is disabled"
    }

    if ((Get-WebConfiguration -Filter 'system.webServer/security/isapiCgiRestriction' -PSPath "IIS:\sites\$appName").notListedCgisAllowed){
        Write-Output "[-] $appName notListedCgisAllowed is NOT disabled"
    } else {
        Write-Output "[+] $appName  notListedCgisAllowed is disabled"
    }
}

###################
Write-Output "`n[*] Ensure ‘Dynamic IP Address Restrictions’ is enabled"
###################
# TODO: What should these settings be
If ((Get-WindowsFeature Web-Ip-Security).Installed -EQ $true) {
    Get-Website | Foreach-Object {
        $appName = $_.Name
        $config = Get-WebConfiguration -Filter '/system.webServer/security/dynamicIpSecurity' -PSPath "IIS:\sites\$appName"

        $denyByConcurrentRequests = $config.denyByConcurrentRequests.enabled
        $denyByRequestRate = $config.denyByRequestRate.enabled

        Write-Output "[-] $appName  Dynamic IP Address Restrictions denyByConcurrentRequests is set to: $denyByConcurrentRequests"
        Write-Output "[-] $appName  Dynamic IP Address Restrictions denyByRequestRate is set to: $denyByRequestRate"
    }
}

###################
Write-Output "`n[*] Ensure Default IIS weblog configuration"
###################
# TODO: What should these settings be
Get-Website | Foreach-Object {
    $appName = $_.Name
    $logDir = $_.logFile.Directory
    $etwLogging = $_.logFile.logTargetW3C

    Write-Output "[-] $appName  IIS weblog location is set to: $logDir"
    Write-Output "[-] $appName  ETW Logging Set to is set to: $etwLogging"
}

###################
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
Write-Output "`n[*] Ensure HSTS Header is set"
###################
# TODO: What should these settings be
Get-Website | Foreach-Object {
    $appName = $_.Name
    $config = (Get-WebConfiguration -Filter '/system.webServer/httpProtocol' -PSPath "IIS:\sites\$appName").customHeaders
    $value  = ($config.Attributes | Where-Object Name -EQ 'Strict-Transport-Security').Value
    $tValue = ''

    if ($value){
        $tValue = $value | Where-Object { $_ -Match "max-age" }
    }

    if ($tValue){
        Write-Output "[-] $appName  HSTS Header is set"
    } else {
        Write-Output "[-] $appName  HSTS Header is NOT set"
    }
}

###################
Write-Output "`n[*] Ensure SSLv2 is Disabled"
###################
$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0"

If ((Test-Path -Path $path) -and (Test-Path -Path "$path\Server")) {
    $Key = Get-Item "$path\Server"

    if ($null -ne $Key.GetValue("Enabled", $null)) {
        $value = Get-ItemProperty "$path\Server" | Select-Object -ExpandProperty "Enabled"
        # Ensure it is set to 0
        if ($value -ne 0) {
            Write-Output "[-] SSLv2 is NOT disabled"
        } Else {
            Write-Output "[+] SSLv2 is disabled"
        }
    }
} else {
    # TODO: should this be disabled?
    Write-Output "[-] $path keys not found"
}

###################
Write-Output "`n[*] Ensure SSLv3 is Disabled"
###################
$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0"

If ((Test-Path -Path $path) -and (Test-Path -Path "$path\Server")) {
    $Key = Get-Item "$path\Server"

    if ($null -ne $Key.GetValue("Enabled", $null)) {
        $value = Get-ItemProperty "$path\Server" | Select-Object -ExpandProperty "Enabled"
        # Ensure it is set to 0
        if ($value -ne 0) {
            Write-Output "[-] SSLv3 is NOT disabled"
        } Else {
            Write-Output "[+] SSLv3 is disabled"
        }
    }
} else {
    # TODO: should this be disabled?
    Write-Output "[-] $path keys not found"
}

###################
Write-Output "`n[*] Ensure TLS 1.0 is Disabled"
###################
$path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"

If ((Test-Path -Path $path)) {
    $Key = Get-Item "$path"

    if ($null -ne $Key.GetValue("Enabled", $null)) {
        $value = Get-ItemProperty "$path\Server" | Select-Object -ExpandProperty "Enabled"
        # Ensure it is set to 0
        if ($value -ne 0) {
            Write-Output "[-] TLSv1 is NOT disabled"
        } Else {
            Write-Output "[+] TLSv1 is disabled"
        }
    }
} else {
    # TODO: should this be disabled?
    Write-Output "[-] $path keys not found"
}

###################
Write-Output "`n[*] Ensure TLS 1.1 is Disabled"
###################
$path = “HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server”

If ((Test-Path -Path $path)) {
    $Key = Get-Item "$path"

    if ($null -ne $Key.GetValue("Enabled", $null)) {
        $value = Get-ItemProperty "$path\Server" | Select-Object -ExpandProperty "Enabled"
        # Ensure it is set to 0
        if ($value -ne 0) {
            Write-Output "[-] TLSv1.1 is NOT disabled"
        } Else {
            Write-Output "[+] TLSv1.1 is disabled"
        }
    }
} else {
    # TODO: should this be disabled?
    Write-Output "[-] $path keys not found"
}

