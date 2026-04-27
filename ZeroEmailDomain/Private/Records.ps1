function Get-ZedDesiredEmailProtectionRecord {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateRange(60, 86400)]
        [int]$Ttl = 3600
    )

    [PSCustomObject]@{
        Type        = 'TXT'
        Name        = '@'
        Content     = 'v=spf1 -all'
        Ttl         = $Ttl
        MatchPrefix = 'v=spf1'
    }

    [PSCustomObject]@{
        Type        = 'TXT'
        Name        = '*._domainkey'
        Content     = 'v=DKIM1; p='
        Ttl         = $Ttl
        MatchPrefix = 'v=DKIM1'
    }

    [PSCustomObject]@{
        Type        = 'TXT'
        Name        = '_dmarc'
        Content     = 'v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s'
        Ttl         = $Ttl
        MatchPrefix = 'v=DMARC1'
    }
}
