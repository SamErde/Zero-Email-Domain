function Set-ParkRangerProtection {
    <#
    .SYNOPSIS
        Applies deny-all email DNS records to domains that do not receive email.

    .DESCRIPTION
        Enumerates DNS zones from a provider, skips zones that have MX records,
        and creates or updates SPF, DKIM, and DMARC TXT records that instruct
        receivers to reject mail claiming to be from the domain.

    .PARAMETER Provider
        DNS provider to use. Cloudflare is currently implemented. AzureDns,
        Route53, GoDaddy, and Namecheap are registered extension points.

    .PARAMETER CloudflareApiToken
        Cloudflare API token as a SecureString. The token needs Zone:Read and
        DNS:Edit permissions scoped to the target zones.

    .PARAMETER CloudflareBaseUri
        Cloudflare API base URI. Defaults to the public v4 endpoint.

    .PARAMETER CloudflarePageSize
        Number of Cloudflare results to request per page. Cloudflare supports a
        maximum of 50 for these endpoints.

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
        Set-ParkRangerProtection -Provider Cloudflare -CloudflareApiToken $Token -WhatIf

    .OUTPUTS
        PSCustomObject when PassThru is specified.

    .NOTES
        Cloudflare is currently the only implemented DNS provider. Other
        providers are registered as explicit extension points and fail closed
        until implemented.
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

    begin {
        try {
            $providerDefinition = Get-ParkRangerDnsProvider -Name $Provider
            Confirm-ParkRangerDnsProviderImplemented -Provider $providerDefinition
            $providerContext = Get-ParkRangerDnsProviderContext -Provider $providerDefinition -CloudflareApiToken $CloudflareApiToken -CloudflareBaseUri $CloudflareBaseUri -CloudflarePageSize $CloudflarePageSize
            $desiredRecords = Get-ParkRangerDesiredEmailProtectionRecordSet -Ttl $Ttl
        } catch {
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }

    end {
        try {
            foreach ($zone in (Get-ParkRangerDnsZone -Context $providerContext -ZoneName $ZoneName)) {
                Write-Verbose "Evaluating zone '$($zone.Name)' with provider '$Provider'."

                if (Test-ParkRangerDnsZoneHasMxRecord -Context $providerContext -Zone $zone) {
                    Write-Verbose "Skipping zone '$($zone.Name)' because it has MX records."

                    if ($PassThru.IsPresent) {
                        [PSCustomObject]@{
                            Provider   = $Provider
                            ZoneName   = $zone.Name
                            RecordName = $null
                            Content    = $null
                            Action     = 'SkippedHasMx'
                            RecordId   = $null
                        }
                    }

                    continue
                }

                foreach ($record in $desiredRecords) {
                    $target = '{0}:{1}' -f $zone.Name, $record.Name
                    $action = "Set $($record.Type) record to '$($record.Content)'"

                    if (-not $PSCmdlet.ShouldProcess($target, $action)) {
                        continue
                    }

                    $result = Invoke-ParkRangerDnsTxtRecordSync -Context $providerContext -Zone $zone -Record $record

                    if ($PassThru.IsPresent) {
                        [PSCustomObject]@{
                            Provider   = $Provider
                            ZoneName   = $zone.Name
                            RecordName = $result.Name
                            Content    = $record.Content
                            Action     = $result.Action
                            RecordId   = $result.Id
                        }
                    }
                }
            }
        } catch {
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }
}
