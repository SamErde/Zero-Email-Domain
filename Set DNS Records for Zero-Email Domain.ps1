<#
.SYNOPSIS
    Legacy compatibility wrapper for protecting domains that do not send email.

.DESCRIPTION
    This script is being replaced by the ZeroEmailDomain PowerShell module and
    the Protect-ZeroEmailDomain.ps1 entry point. It remains in the repository
    root temporarily so existing automation can transition to the new command
    name without immediately breaking.

.PARAMETER Provider
    DNS provider to use. Cloudflare is currently implemented. AzureDns,
    Route53, GoDaddy, and Namecheap are registered extension points.

.PARAMETER CloudflareApiToken
    Cloudflare API token as a SecureString. The token needs Zone:Read and
    DNS:Edit permissions scoped to the target zones.

.PARAMETER CloudflareBaseUri
    Cloudflare API base URI. Defaults to the public v4 endpoint.

.PARAMETER CloudflarePageSize
    Number of Cloudflare results to request per page.

.PARAMETER ZoneName
    Optional zone names to process. When omitted, every visible zone is
    evaluated.

.PARAMETER Ttl
    TTL in seconds for created or updated TXT records.

.PARAMETER PassThru
    Outputs a result object for each skipped, created, updated, or unchanged
    record.

.EXAMPLE
    # Set $Token to a SecureString from your preferred secret manager.
    .\Set DNS Records for Zero-Email Domain.ps1 -Provider Cloudflare -CloudflareApiToken $Token -WhatIf

.OUTPUTS
    PSCustomObject when PassThru is specified.

.NOTES
    Prefer Protect-ZeroEmailDomain.ps1 or the Protect-ZeroEmailDomain function
    from the ZeroEmailDomain module for new automation.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter()]
    [ValidateSet('Cloudflare', 'AzureDns', 'Route53', 'GoDaddy', 'Namecheap')]
    [string]$Provider = 'Cloudflare',

    [Parameter()]
    [SecureString]$CloudflareApiToken,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CloudflareBaseUri = 'https://api.cloudflare.com/client/v4',

    [Parameter()]
    [ValidateRange(1, 50)]
    [int]$CloudflarePageSize = 50,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$ZoneName,

    [Parameter()]
    [ValidateRange(60, 86400)]
    [int]$Ttl = 3600,

    [Parameter()]
    [switch]$PassThru
)

$moduleRoot = Join-Path -Path $PSScriptRoot -ChildPath 'ZeroEmailDomain'
$modulePath = Join-Path -Path $moduleRoot -ChildPath 'ZeroEmailDomain.psd1'
Import-Module -Name $modulePath -Force

Protect-ZeroEmailDomain @PSBoundParameters
