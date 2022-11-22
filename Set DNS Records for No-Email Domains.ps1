<#
.SYNOPSIS
    Create DNS records for email security in domains that do not use email.

.DESCRIPTION
    This script will check your Cloudflare account (or the scope that your API token has access to)
    for zones (domains) that do not contain MX records. For those zones that do not use email, it will 
    create SPF, DKIM, and DMARC messages indicating that all messages should be rejected for the domain.

.NOTES
  Version:  0.5
  Author:   Sam Erde
  Date:     2022-02-07

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

#==============================================================================
#region Declare variables
# Inputs ======================================================================

# Capture the current path of the script, or use the working directory if run at the console.
if ($PSScriptRoot) {
    $ScriptPath = $PSScriptRoot
}
else {
    $ScriptPath = $pwd
}

# Use if the API token is stored in a text file, which should also be listed in .gitignore.
$ApiTokenTextFilePath = "$ScriptPath\APIToken.txt"
# If the text file does not exist, prompt the user to enter their API token.
if (Test-Path $ApiTokenTextFilePath) {
    $CloudflareApiToken = Get-Content $ApiTokenTextFilePath | ConvertTo-SecureString -AsPlainText -Force
}
else {
    $CloudflareApiToken = Read-Host -Prompt "Please enter your Cloudflare API token" -MaskInput | ConvertTo-SecureString -AsPlainText -Force
}

$BaseUri = 'https://api.cloudflare.com/client/v4'
$Params = @{
    Uri = "$BaseUri/zones"
    Authentication = "Bearer"
    Token = $CloudflareApiToken
}
$ZoneCount = (Invoke-RestMethod @Params -SessionVariable "ApiSession").result_info.total_count

# Outputs =====================================================================
$LogFilePath = "$ScriptPath\Set DNS Record for No Email.log"
$NoMxDomains = [System.Collections.ArrayList]::new()
$MxDomains = [System.Collections.ArrayList]::new()

# SPF record for a domain that does not use email:
$SpfRecord = @{
    "type" = "TXT"
    "name" = "@"
    "content" = "v=spf1 -all"
} | ConvertTo-Json
# DKIM record for a domain that does not use email:
$DkimRecord = @{
    "type" = "TXT"
    "name" = "*._domainkey"
    "content" = "v=DKIM1; p="
} | ConvertTo-Json
# DMARC record for a domain that does not use email:
$DmarcRecord = @{
    "type" = "TXT"
    "name" = "_dmarc"
    "content" = "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;"
} | ConvertTo-Json

# Combined DNS records:
$EmailSecurityRecords = @($SpfRecord,$DkimRecord,$DmarcRecord)
#endregion
#==============================================================================

# Get the first 100 zones that are readble by the API token.
$Zones = (Invoke-RestMethod -WebSession $ApiSession -Uri "$BaseUri/zones/?per_page=$ZoneCount").result


# Check each zone for the presence of MX records and group by those with/without.
foreach ($zone in ($zones)) {
    $MxRecords = (Invoke-RestMethod -WebSession $ApiSession -Uri "$BaseUri/zones/$($zone.id)/dns_records?type=MX").result
    if ($MxRecords.Count -gt 0) {
        $MxDomains.Add($zone) | Out-Null
    }
    else {
        $NoMxDomains.Add($zone) | Out-Null
    }
}


Get-Date | Add-Content $LogFilePath
foreach ($Zone in $($NoMxDomains)) {
    Write-Output "$($Zone.id), $($Zone.name)" | Add-Content $LogFilePath
    # Loop through the three email security records and create each one.
    foreach ($item in $EmailSecurityRecords) {
        $PostParams = @{
            Uri = "$BaseUri/zones/$($Zone.id)/dns_records/"
            Body = $item
            Method = 'Post'
            Authentication = 'Bearer'
            Token = $CloudflareApiToken
        }
        $PostResults = Invoke-RestMethod @PostParams -ErrorAction SilentlyContinue
        $PostResults.result | Add-Content -Path $LogFilePath
    }
}
