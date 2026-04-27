function Get-ParkRangerDnsProvider {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter()]
        [ValidateSet('Cloudflare', 'AzureDns', 'Route53', 'GoDaddy', 'Namecheap')]
        [string]$Name
    )

    $providers = @(
        [PSCustomObject]@{
            Name           = 'Cloudflare'
            IsImplemented  = $true
            RequiredModule = $null
            Notes          = 'Uses the Cloudflare v4 REST API.'
        }
        [PSCustomObject]@{
            Name           = 'AzureDns'
            IsImplemented  = $false
            RequiredModule = 'Az.Dns'
            Notes          = 'Planned provider using Azure DNS record-set cmdlets.'
        }
        [PSCustomObject]@{
            Name           = 'Route53'
            IsImplemented  = $false
            RequiredModule = 'AWS.Tools.Route53'
            Notes          = 'Planned provider using AWS Route 53 hosted zones.'
        }
        [PSCustomObject]@{
            Name           = 'GoDaddy'
            IsImplemented  = $false
            RequiredModule = $null
            Notes          = 'Planned provider using the GoDaddy Domains API.'
        }
        [PSCustomObject]@{
            Name           = 'Namecheap'
            IsImplemented  = $false
            RequiredModule = $null
            Notes          = 'Planned provider using the Namecheap XML API.'
        }
    )

    if ($Name) {
        return $providers | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    }

    $providers
}

function Confirm-ParkRangerDnsProviderImplemented {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Provider
    )

    if ($Provider.IsImplemented) {
        return
    }

    $message = "Provider '$($Provider.Name)' is registered but not implemented yet. $($Provider.Notes)"
    throw [System.NotSupportedException]::new($message)
}

function Get-ParkRangerDnsProviderContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Provider,

        [Parameter()]
        [SecureString]$CloudflareApiToken,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$CloudflareBaseUri = 'https://api.cloudflare.com/client/v4',

        [Parameter()]
        [ValidateRange(1, 50)]
        [int]$CloudflarePageSize = 50
    )

    switch ($Provider.Name) {
        'Cloudflare' {
            if ($null -eq $CloudflareApiToken) {
                throw [InvalidOperationException]::new('CloudflareApiToken is required when Provider is Cloudflare.')
            }

            return Get-ParkRangerCloudflareContext -ApiToken $CloudflareApiToken -BaseUri $CloudflareBaseUri -PageSize $CloudflarePageSize
        }
        default {
            Confirm-ParkRangerDnsProviderImplemented -Provider $Provider
        }
    }
}

function Get-ParkRangerDnsZone {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter()]
        [string[]]$ZoneName
    )

    switch ($Context.Provider) {
        'Cloudflare' {
            Get-ParkRangerCloudflareZone -Context $Context -ZoneName $ZoneName
        }
        default {
            throw [System.NotSupportedException]::new("Provider '$($Context.Provider)' is not implemented.")
        }
    }
}

function Test-ParkRangerDnsZoneHasMxRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory)]
        [object]$Zone
    )

    switch ($Context.Provider) {
        'Cloudflare' {
            Test-ParkRangerCloudflareZoneHasMxRecord -Context $Context -Zone $Zone
        }
        default {
            throw [System.NotSupportedException]::new("Provider '$($Context.Provider)' is not implemented.")
        }
    }
}

function Invoke-ParkRangerDnsTxtRecordSync {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory)]
        [object]$Zone,

        [Parameter(Mandatory)]
        [object]$Record
    )

    switch ($Context.Provider) {
        'Cloudflare' {
            Invoke-ParkRangerCloudflareTxtRecordSync -Context $Context -Zone $Zone -Record $Record
        }
        default {
            throw [System.NotSupportedException]::new("Provider '$($Context.Provider)' is not implemented.")
        }
    }
}
