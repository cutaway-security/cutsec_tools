##########################################################################
# CPEtoCVE
# Version 1.0.0
# Obtain a list of published CVEs from a list of CPEs
#
# Resources:
#         https://github.com/robvandenbrink/CVEScan
#
# NVD Developer Instructions:
#         https://nvd.nist.gov/developers
#
#         Request an API Key
#         On the API key requests page, enter data into the three fields on the requests form.
#         Scroll to the bottom of the Terms of Use, and then click the check box marked “I agree to the Terms of Use.”
#         Check the inbox of the email address provided in the steps above for an email from nvd-noreply@nist.gov.
#         Activate and view the API Key by opening the single-use hyperlink. Store the API Key in a secure location as 
#         the page will no longer be available after it is closed. If your key is not activated within seven days, a request 
#         for a new API Key must be submitted.
#
#         Rate Limits
#         Requesting an API key allows for users to make a greater number of requests in a given time than they could otherwise. 
#         The public rate limit (without an API key) is 10 requests in a rolling 60 second window; the rate limit with an API key 
#         is 100 requests in a rolling 60 second window.
#         The best practice for making requests within the rate limit is to use the modified date parameters. No more than once 
#         every two hours, automated requests should include a range where modStartDate equals the time of the last CVE or CPE 
#         received and modEndDate equals the current time. Enterprise scale development should enforce this approach through a 
#         single requestor to ensure all users are in sync and have the latest CVE and CPE information. It is also recommended 
#         that users "sleep" their scripts for six seconds between requests.
# 
# Syntax:
#         CPEtoCVE.ps1 [-h] [-o] [-d <seconds] [-a <apikey>] -i <filename>
#
##########################################################################
<#
Process to obtain CPE's for software:
 
    Identify the CPE for the software by searching the NVD NIST Website
        https://nvd.nist.gov/products/cpe/search
    Obtain the CPEv2.3 string for the software.
        Search for ‘Apache AVRO’ identifies multiple CPEv2.3 strings.
        Pick one and modify it to the correct version or where the version field is a wild card. 
            For AVRO version 1.10.1 the string ‘cpe:2.3:a:apache:avro:1.10.1:*:*:*:*:*:*:*’ becomes
                cpe:2.3:a:apache:avro:1.9.1:*:*:*:*:*:*:* or
                cpe:2.3:a:apache:avro:*:*:*:*:*:*:*:*
            NOTE: Searching for this in the NVD search field will show if it is a valid string
            NOTE: Sometimes this doesn’t work, but Googling “apache avro CPE” will return a useable string to search in NVD NIST
    Save all the CPE entries into a text file, one per line, and save.
    Run the script CPEtoCVE.ps1 (works in OSX pwsh and should work in Linux and Windows)
    CPEtoCVE.ps1 -i <cpe_file.txt> -o
    This will write the output to the file cpe_file_<timestamp>.txt
#>

param (
    [alias("a")] $apikey,
    [alias("i")] $infile,
    [alias("d")] $delay  = 1,
    [alias("o")][switch] $outfile,
    [alias("h")][switch] $help
)

Function Get-Usage {
    Write-Output "CPEtoCVE: Collect a list of CVEs from a list of CPEs"
    Write-Output "Parameters:"
    Write-Output "    -a <apikey>   : Provide user's API key [not required]"
    Write-Output "    -i <filename> : Provide a file with CPE entries [required]"
    Write-Output "    -d <seconds>  : delay in seconds [Default: 1]"
    Write-Output "    -o            : Print to an output file and Stdout, renamed from input filename [Default: Stdout]"
    Write-Output "    -h            : display this message`n"
    Write-Output "Usage: CPEtoCVE.ps1 [-h] [-o] [-d <seconds] [-a <apikey>] -i <filename>`n"
    Exit
}

if($help -or -not ($infile)){Get-Usage}

# Setup
$allCVEs = @()
$apps    = Get-Content $infile
$now     = Get-Date 
if ($outfile){
    $logfile = $infile.replace(".txt","_" + $now.tostring("yyy-MM-dd_hh-mm") + "_CVE.txt")
}

# Handle values copied out of a spreadsheet with values contained in double quotes
$tempCPEs = @()
ForEach ($appCPEs in $apps) {
    if (($appCPEs -eq "None") -or ($appCPEs -eq "")){ Continue }
    $tempCPEs += $appCPEs.replace("`"","").split(' ')
}

# Convert CPE value to CVEs List
ForEach ($appCPE in $tempCPEs){
    # Request CVEs using CPE value
    $request = "https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString=$appCPE&$apikey"
    $CVEs = (Invoke-WebRequest $request -UseBasicParsing | ConvertFrom-Json).result.CVE_Items
    
    # Loop through each CVE and extract the data
    ForEach ($CVE in $CVEs) {
        $cveId = $CVE.cve.CVE_data_meta.ID
        $cvssV2 = $CVE.impact.baseMetricV2.impactScore
        $cvssV3 = $CVE.impact.baseMetricV3.impactScore
        $cveDesc = $CVE.cve.description.description_data.Where({$_.lang -eq "en"}).value
        if ($cvssV3){            
            #$exScore = $CVE.impact.baseMetricV3.exploitabilityScore
            #$vecString = $CVE.impact.baseMetricV3.cvssV3.vectorString
            $allCVEs += $cveId + " cvssV3: " + $cvssV2 + " `"" + $cveDesc + "`""
        } else{
            #$exScore = $CVE.impact.baseMetricV2.exploitabilityScore
            #$vecString = $CVE.impact.baseMetricV2.cvssV2.vectorString
            $allCVEs += $cveId + " cvssV2: " + $cvssV2 + " `"" + $cveDesc + "`""
        }
    }
    
    # Write output to the sceen and also to a file in the local directory
    if($outfile){
        "CVEs for $appCPE :" | Tee-Object -Append -FilePath $logfile
        ForEach ($c in ($allCVEs | Sort-Object | Get-Unique)){ 
            $c | Tee-Object -Append -FilePath $logfile
        }
    }else{
        "CVEs for $appCPE :" 
        ForEach ($c in ($allCVEs | Sort-Object | Get-Unique)){ 
            $c 
        }
    }
    # Add a delay to comply with API settings
    Start-Sleep -s $delay
    Write-Output "`n`n"
}
