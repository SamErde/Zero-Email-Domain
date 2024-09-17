# I Need a Better Name

Automatically create "reject all" SPF, DKIM, and DMARC DNS records in domains that contain no MX records.

This is an quick concept that I made using PowerShell and the Cloudflare API so I could quickly achieve this task for the 60+ domains that I was responsible for. 

## Requirements

  - [x] A Cloudflare account
  - [x] At least one domain that uses Cloudflare managed DNS
  - [x] A Cloudflare API token that has permissions to view the zone[s] and edit DNS records in the zone[s]
  - [x] PowerShell

## To Do

  - [ ] Create documentation.
  - [ ] Better handling of API keys.
  - [ ] Improve API usage and add paging.
