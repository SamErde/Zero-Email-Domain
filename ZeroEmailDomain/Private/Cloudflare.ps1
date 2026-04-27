function Get-ZedCloudflareContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [SecureString]$ApiToken,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$BaseUri,

        [Parameter(Mandatory)]
        [ValidateRange(1, 50)]
        [int]$PageSize
    )

    [PSCustomObject]@{
        Provider = 'Cloudflare'
        ApiToken = $ApiToken
        BaseUri  = $BaseUri.TrimEnd('/')
        PageSize = $PageSize
    }
}

function Join-ZedQueryString {
    [CmdletBinding()]
    param(
        [Parameter()]
        [hashtable]$Query
    )

    if ($null -eq $Query -or $Query.Count -eq 0) {
        return ''
    }

    $pairs = foreach ($key in ($Query.Keys | Sort-Object)) {
        if ($null -eq $Query[$key] -or $Query[$key] -eq '') {
            continue
        }

        '{0}={1}' -f [Uri]::EscapeDataString([string]$key), [Uri]::EscapeDataString([string]$Query[$key])
    }

    if ($pairs.Count -eq 0) {
        return ''
    }

    '?{0}' -f ($pairs -join '&')
}

function Get-ZedCloudflareErrorMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Response
    )

    $messages = @(
        foreach ($errorItem in @($Response.errors)) {
            if ($errorItem.message) {
                $errorItem.message
            }
        }
    )

    if ($messages.Count -gt 0) {
        return ($messages -join '; ')
    }

    'Cloudflare API request failed.'
}

function Invoke-ZedCloudflareRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory)]
        [ValidateSet('Get', 'Post', 'Put', 'Patch', 'Delete')]
        [string]$Method,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter()]
        [hashtable]$Query,

        [Parameter()]
        [hashtable]$Body
    )

    $relativePath = $Path.TrimStart('/')
    $uri = '{0}/{1}{2}' -f $Context.BaseUri, $relativePath, (Join-ZedQueryString -Query $Query)
    $requestParameters = @{
        Uri            = $uri
        Method         = $Method
        Authentication = 'Bearer'
        Token          = $Context.ApiToken
        ErrorAction    = 'Stop'
    }

    if ($PSBoundParameters.ContainsKey('Body')) {
        $requestParameters.ContentType = 'application/json'
        $requestParameters.Body = $Body | ConvertTo-Json -Depth 10
    }

    $response = Invoke-RestMethod @requestParameters

    if ($response.success -ne $true) {
        throw [InvalidOperationException]::new((Get-ZedCloudflareErrorMessage -Response $response))
    }

    $response
}

function Get-ZedCloudflarePagedResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter()]
        [hashtable]$Query,

        [Parameter()]
        [ValidateRange(1, 50)]
        [int]$PageSize = $Context.PageSize
    )

    $page = 1

    do {
        $pageQuery = @{}
        if ($null -ne $Query) {
            foreach ($key in $Query.Keys) {
                $pageQuery[$key] = $Query[$key]
            }
        }

        $pageQuery.page = $page
        $pageQuery.per_page = $PageSize

        $response = Invoke-ZedCloudflareRequest -Context $Context -Method Get -Path $Path -Query $pageQuery
        $items = if ($null -eq $response.result) { @() } else { @($response.result) }

        foreach ($item in $items) {
            $item
        }

        $resultInfo = $response.result_info
        if ($null -ne $resultInfo -and $null -ne $resultInfo.total_pages) {
            $hasMore = $page -lt [int]$resultInfo.total_pages
        } else {
            $hasMore = $items.Count -eq $PageSize
        }

        $page++
    } while ($hasMore)
}

function Get-ZedCloudflareZone {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter()]
        [string[]]$ZoneName
    )

    if ($ZoneName) {
        foreach ($name in $ZoneName) {
            Get-ZedCloudflarePagedResult -Context $Context -Path 'zones' -Query @{ name = $name } |
                ForEach-Object {
                    [PSCustomObject]@{
                        Provider     = 'Cloudflare'
                        Id           = $_.id
                        Name         = $_.name
                        ProviderZone = $_
                    }
                }
        }

        return
    }

    Get-ZedCloudflarePagedResult -Context $Context -Path 'zones' |
        ForEach-Object {
            [PSCustomObject]@{
                Provider     = 'Cloudflare'
                Id           = $_.id
                Name         = $_.name
                ProviderZone = $_
            }
        }
}

function Get-ZedCloudflareDnsRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ZoneId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RecordType,

        [Parameter()]
        [string]$RecordName
    )

    $query = @{
        type = $RecordType
    }

    if ($RecordName) {
        $query.name = $RecordName
    }

    Get-ZedCloudflarePagedResult -Context $Context -Path "zones/$ZoneId/dns_records" -Query $query
}

function Test-ZedCloudflareZoneHasMxRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory)]
        [object]$Zone
    )

    $response = Invoke-ZedCloudflareRequest -Context $Context -Method Get -Path "zones/$($Zone.Id)/dns_records" -Query @{
        type     = 'MX'
        page     = 1
        per_page = 1
    }

    if ($null -ne $response.result_info -and $null -ne $response.result_info.total_count) {
        return [int]$response.result_info.total_count -gt 0
    }

    $resultItems = if ($null -eq $response.result) { @() } else { @($response.result) }
    $resultItems.Count -gt 0
}

function ConvertTo-ZedCloudflareRecordName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RecordName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ZoneName
    )

    if ($RecordName -eq '@') {
        return $ZoneName
    }

    if ($RecordName.Equals($ZoneName, [System.StringComparison]::OrdinalIgnoreCase) -or
        $RecordName.EndsWith(".$ZoneName", [System.StringComparison]::OrdinalIgnoreCase)) {
        return $RecordName
    }

    '{0}.{1}' -f $RecordName, $ZoneName
}

function Find-ZedDnsTxtRecord {
    [CmdletBinding()]
    param(
        [Parameter()]
        [object[]]$Record,

        [Parameter(Mandatory)]
        [object]$DesiredRecord
    )

    $records = @($Record)
    $exactMatch = $records |
        Where-Object { $_.content -eq $DesiredRecord.Content } |
        Select-Object -First 1

    if ($exactMatch) {
        return [PSCustomObject]@{
            MatchType = 'Exact'
            Record    = $exactMatch
        }
    }

    $prefixMatch = $records |
        Where-Object { $_.content -like "$($DesiredRecord.MatchPrefix)*" } |
        Select-Object -First 1

    if ($prefixMatch) {
        return [PSCustomObject]@{
            MatchType = 'Prefix'
            Record    = $prefixMatch
        }
    }

    [PSCustomObject]@{
        MatchType = 'None'
        Record    = $null
    }
}

function Invoke-ZedCloudflareTxtRecordSync {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory)]
        [object]$Zone,

        [Parameter(Mandatory)]
        [object]$Record
    )

    $recordName = ConvertTo-ZedCloudflareRecordName -RecordName $Record.Name -ZoneName $Zone.Name
    $existingRecords = Get-ZedCloudflareDnsRecord -Context $Context -ZoneId $Zone.Id -RecordType TXT -RecordName $recordName
    $match = Find-ZedDnsTxtRecord -Record $existingRecords -DesiredRecord $Record

    if ($match.MatchType -eq 'Exact') {
        return [PSCustomObject]@{
            Action = 'Unchanged'
            Id     = $match.Record.id
            Name   = $recordName
        }
    }

    $body = @{
        type    = 'TXT'
        name    = $recordName
        content = $Record.Content
        ttl     = $Record.Ttl
    }

    if ($match.MatchType -eq 'Prefix') {
        $response = Invoke-ZedCloudflareRequest -Context $Context -Method Put -Path "zones/$($Zone.Id)/dns_records/$($match.Record.id)" -Body $body

        return [PSCustomObject]@{
            Action = 'Updated'
            Id     = $response.result.id
            Name   = $recordName
        }
    }

    $createResponse = Invoke-ZedCloudflareRequest -Context $Context -Method Post -Path "zones/$($Zone.Id)/dns_records" -Body $body

    [PSCustomObject]@{
        Action = 'Created'
        Id     = $createResponse.result.id
        Name   = $recordName
    }
}
