# No-Email-Security
Automatically create "reject all" SPF, DKIM, and DMARC DNS records in domains that contain no MX records.

This is an quick concept that I made using PowerShell and the Cloudflare API so I could quickly achieve this task for the 60+ domains that I am responsible for. 

## Requirements
 - A Cloudflare account
 - At least one domain that uses Cloudflare managed DNS
 - A Cloudflare API token that has permissions to view the zone[s] and edit DNS records in the zone[s]
 - Windows PowerShell 5.1 or PowerShell [Core] 6.0 and higher

## How to Use
### Create Cloudflare Token

### Do stuff...
