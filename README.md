# Zero Email Domain

Automatically create "reject all" SPF, DKIM, and DMARC DNS records in domains
that contain no MX records.

This project is being transitioned from the original Cloudflare-only script to a
PowerShell module plus thin command scripts. The current implementation supports
Cloudflare and is designed so other DNS providers can be added behind the same
orchestration logic.

The original `Set DNS Records for Zero-Email Domain.ps1` file remains in the
repository root as a temporary compatibility wrapper. New automation should use
`Protect-ZeroEmailDomain.ps1` or import the `ZeroEmailDomain` module and call
`Protect-ZeroEmailDomain`.

## Requirements

- PowerShell 7.2 or later
- For Cloudflare:
  - A Cloudflare API token with `Zone:Read` and `DNS:Edit` permissions
  - At least one Cloudflare-managed DNS zone

## Usage

Preview the changes before writing records:

```powershell
# Set $Token to a SecureString from your preferred secret manager.
.\Protect-ZeroEmailDomain.ps1 -Provider Cloudflare -CloudflareApiToken $Token -WhatIf
```

Apply records and return structured results:

```powershell
# Set $Token to a SecureString from your preferred secret manager.
.\Protect-ZeroEmailDomain.ps1 -Provider Cloudflare -CloudflareApiToken $Token -PassThru
```

Limit processing to specific zones:

```powershell
# Set $Token to a SecureString from your preferred secret manager.
.\Protect-ZeroEmailDomain.ps1 `
    -Provider Cloudflare `
    -CloudflareApiToken $Token `
    -ZoneName 'example.com', 'example.net' `
    -PassThru
```

## Records

For zones without MX records, the command creates or updates these TXT records:

| Purpose | Name | Content |
| --- | --- | --- |
| SPF | `@` | `v=spf1 -all` |
| DKIM | `*._domainkey` | `v=DKIM1; p=` |
| DMARC | `_dmarc` | `v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s` |

The command skips zones that already have MX records.

## Provider support

| Provider | Status | Notes |
| --- | --- | --- |
| Cloudflare | Implemented | Uses the Cloudflare v4 REST API with tested paging. |
| Azure DNS | Planned | Extension point registered for a future `Az.Dns` provider. |
| AWS Route 53 | Planned | Extension point registered for a future `AWS.Tools.Route53` provider. |
| GoDaddy | Planned | Extension point registered for the GoDaddy Domains API. |
| Namecheap | Planned | Extension point registered for the Namecheap XML API. |

Unsupported providers fail closed with a clear error instead of silently doing
nothing.

## Security notes

- Do not store API tokens in repository files.
- Use `-WhatIf` before applying records to a new account or zone set.
- Scope provider credentials to the minimum required zones and permissions.
- The Cloudflare implementation does not suppress API errors; failed requests
  stop execution with the provider error message.

## Development

Run the Pester tests:

```powershell
Invoke-Pester -Path .\Tests
```

## To Do

- [ ] Implement Azure DNS provider.
- [ ] Implement AWS Route 53 provider.
- [ ] Implement GoDaddy provider.
- [ ] Implement Namecheap provider.
