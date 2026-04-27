@{
    RootModule        = 'ParkRanger.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'be5cf9cb-93c0-4e25-8a61-f39b9773bdb2'
    Author            = 'Sam Erde'
    CompanyName       = 'Unknown'
    Copyright         = '(c) Sam Erde. All rights reserved.'
    Description       = 'ParkRanger sets deny-all email DNS records for domains that do not receive email.'
    PowerShellVersion = '7.2'
    FunctionsToExport = @('Set-ParkRangerProtection')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('DNS', 'SPF', 'DKIM', 'DMARC', 'Cloudflare')
            ProjectUri = 'https://github.com/SamErde/ParkRanger'
        }
    }
}
