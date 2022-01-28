<#
.SYNOPSIS
    Create email security DNS records for domains that do not use email.

.DESCRIPTION
    This script will check your Cloudflare account (or any accounts that a given API token has access to)
    for zones (domains) that do not contain MX records. For those zones that do not use email, it will 
    create SPF, DKIM, and DMARC messages indicating that all messages should be rejected for the domain.

.NOTES
  Version:  0.5
  Author:   Sam Erde
  Date:     2022-01-28

  Needs:
            Logging
            Error handling
            Check for existence of SPF, DKIM, and DMARC records
            Wrap in functions
            Actually handle pagination in results
    
  Opportunities:
            Add other DNS providers
            Make it a module?
#>

#================================================================================
#region Declare variables
# Inputs ==============================

# Capture the current path of the script, or use the working directory if run at the console.
if ($PSScriptRoot) {
    $ScriptPath = $PSScriptRoot
}
else {
    $ScriptPath = $pwd
}

$CloudflareApiToken = Get-Content "$ScriptPath\APIToken.txt" | ConvertTo-SecureString -AsPlainText -Force

$BaseUri = 'https://api.cloudflare.com/client/v4/zones'

$IrmParams = @{
    Uri = $BaseUri
    Authentication = "Bearer"
    Token = $CloudflareApiToken
}
Invoke-RestMethod @IrmParams -SessionVariable "ApiSession"

# Outputs ==============================
$LogFilePath = "$ScriptPath\Email Security DNS Records.log"
$NoMxDomains = [System.Collections.ArrayList]::new()
$MxDomains = [System.Collections.ArrayList]::new()

# SPF record for a domain that does not use email
$SpfRecord = @{
    "type" = "TXT"
    "name" = "@"
    "content" = "v=spf1 -all"
} | ConvertTo-Json
# DMARC record for a domain that does not use email
$DkimRecord = @{
    "type" = "TXT"
    "name" = "*._domainkey"
    "content" = "v=DKIM1; p="
} | ConvertTo-Json
$DmarcRecord = @{
    "type" = "TXT"
    "name" = "_dmarc"
    "content" = "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;"
} | ConvertTo-Json

$EmailSecurityRecords = @($SpfRecord,$DkimRecord,$DmarcRecord)
#endregion
#================================================================================

# Get the first 100 zones that are readble by the given API token.
$Zones = (Invoke-RestMethod -WebSession $ApiSession -Uri "$BaseUri/?per_page=100").result



# Check each zone for the presence of MX records and group by those with/without.
foreach ($item in ($zones)) {
    $MxRecords = (Invoke-RestMethod -WebSession $ApiSession -Uri "$BaseUri/$($item.id)/dns_records?type=MX").result
    if ($MxRecords.Count -gt 0) {
        $MxDomains.Add($item) | Out-Null
    }
    else {
        $NoMxDomains.Add($item) | Out-Null
    }
}


Get-Date | Add-Content $LogFilePath
foreach ($ZoneId in $($NoMxDomains.id)) {
    # Loop through the three email security records and create each one.
    foreach ($item in $EmailSecurityRecords) {
        $PostParams = @{
            Uri = "$BaseUri/$ZoneId/dns_records/"
            Body = $item
            Method = 'Post'
            Authentication = 'Bearer'
            Token = $CloudflareApiToken
        }
        $PostResults = Invoke-RestMethod @PostParams
        $PostResults.result | Add-Content -Path $LogFilePath
    }
}
