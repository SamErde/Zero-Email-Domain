<#
.SYNOPSIS
    Applies deny-all email DNS records to domains that do not receive email.

.DESCRIPTION
    Imports the ZeroEmailDomain module and calls Protect-ZeroEmailDomain.
    The root script is intentionally thin so provider-specific API logic can
    live in the module and be tested independently.

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
    .\Protect-ZeroEmailDomain.ps1 -Provider Cloudflare -CloudflareApiToken $Token -WhatIf

.OUTPUTS
    PSCustomObject when PassThru is specified.

.NOTES
    This script is the preferred repository-root entry point. The reusable
    implementation lives in the ZeroEmailDomain module.
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
