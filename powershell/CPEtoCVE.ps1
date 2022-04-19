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
#         CPEtoCVE.ps1  -a <apikey> -i <input file>
##########################################################################

param (
    [alias("a")] $apikey,
    [alias("i")] $infile,
    [alias("h")][switch] $help
)

Function Get-Usage {
    Write-Output "CPEtoCVE: Collect a list of CVEs from a list of CPEs"
    Write-Output "Parameters:"
    Write-Output "    -a <apikey>: not required"
    Write-Output "    -i <filename>: required"
    Write-Output "    -h: display this message`n"
    Write-Output "Usage: cvescan [-h] [-a <apikey>] -i <filename>`n"
    Exit
}

if($help -or -not ($infile)){Get-Usage}

# setup
$allCVEs = @()

$apps = Get-Content $infile
$now = Get-Date 
$outfile = $infile.replace(".txt","_" + $now.tostring("yyy-MM-dd_hh-mm") + "_CVE.txt")

# Convert CPE value to CVEs List
foreach ($appCPE in $apps) {
    $request = "https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString=$appCPE&$apikey"

    $CVEs = (invoke-webrequest $request | ConvertFrom-Json).result.CVE_Items
    
    foreach ($CVE in $CVEs) {
        $allCVEs += $CVEs.cve.CVE_data_meta.ID
    }
    
    "CVEs for $appCPE :" | Tee-Object -Append -FilePath $outfile
    ForEach ($c in ($allCVEs | Sort-Object | Get-Unique)){ 
        $c | Tee-Object -Append -FilePath $outfile
    }
    Start-Sleep -s 3
}
