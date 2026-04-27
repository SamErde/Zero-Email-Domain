BeforeDiscovery {
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $moduleRoot = Join-Path -Path $repoRoot -ChildPath 'ZeroEmailDomain'
    $moduleManifest = Join-Path -Path $moduleRoot -ChildPath 'ZeroEmailDomain.psd1'
    Import-Module -Name $moduleManifest -Force
}

Describe 'ZeroEmailDomain records' {
    InModuleScope ZeroEmailDomain {
        It 'returns the deny-all SPF, DKIM, and DMARC TXT records' {
            $records = @(Get-ZedDesiredEmailProtectionRecord -Ttl 600)

            $records | Should -HaveCount 3
            $records[0].Content | Should -BeExactly 'v=spf1 -all'
            $records[1].Content | Should -BeExactly 'v=DKIM1; p='
            $records[2].Content | Should -BeExactly 'v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s'
            $records.Ttl | Should -Be @(600, 600, 600)
        }
    }
}

Describe 'ZeroEmailDomain provider registry' {
    InModuleScope ZeroEmailDomain {
        It 'marks Cloudflare as implemented' {
            $provider = Get-ZedDnsProvider -Name Cloudflare

            $provider.IsImplemented | Should -BeTrue
        }

        It 'fails closed for registered providers that are not implemented' {
            $provider = Get-ZedDnsProvider -Name AzureDns

            { Confirm-ZedDnsProviderImplemented -Provider $provider } | Should -Throw "*not implemented*"
        }
    }
}

Describe 'Cloudflare API helpers' {
    InModuleScope ZeroEmailDomain {
        BeforeEach {
            $secureToken = [SecureString]::new()
            foreach ($character in 'token'.ToCharArray()) {
                $secureToken.AppendChar($character)
            }

            $secureToken.MakeReadOnly()

            $script:Context = [PSCustomObject]@{
                Provider = 'Cloudflare'
                ApiToken = $secureToken
                BaseUri  = 'https://api.cloudflare.com/client/v4'
                PageSize = 2
            }
        }

        It 'encodes query string keys and values' {
            $queryString = Join-ZedQueryString -Query @{
                name = 'example.com'
                type = 'TXT'
            }

            $queryString | Should -Be '?name=example.com&type=TXT'
        }

        It 'returns an empty query string when all values are empty' {
            $queryString = Join-ZedQueryString -Query @{
                name = ''
                type = $null
            }

            $queryString | Should -Be ''
        }

        It 'returns every Cloudflare page' {
            Mock Invoke-RestMethod {
                if ($Uri -match 'page=1') {
                    return [PSCustomObject]@{
                        success     = $true
                        result      = @(
                            [PSCustomObject]@{ id = 'zone-1' },
                            [PSCustomObject]@{ id = 'zone-2' }
                        )
                        result_info = [PSCustomObject]@{
                            page        = 1
                            total_pages = 2
                        }
                    }
                }

                [PSCustomObject]@{
                    success     = $true
                    result      = @([PSCustomObject]@{ id = 'zone-3' })
                    result_info = [PSCustomObject]@{
                        page        = 2
                        total_pages = 2
                    }
                }
            }

            $result = @(Get-ZedCloudflarePagedResult -Context $script:Context -Path 'zones' -PageSize 2)

            $result.id | Should -Be @('zone-1', 'zone-2', 'zone-3')
            Should -Invoke Invoke-RestMethod -Exactly 2
        }

        It 'detects MX records without retrieving every MX record' {
            Mock Invoke-RestMethod {
                [PSCustomObject]@{
                    success     = $true
                    result      = @()
                    result_info = [PSCustomObject]@{
                        total_count = 1
                    }
                }
            }

            $zone = [PSCustomObject]@{
                Id   = 'zone-1'
                Name = 'example.com'
            }

            Test-ZedCloudflareZoneHasMxRecord -Context $script:Context -Zone $zone | Should -BeTrue
            Should -Invoke Invoke-RestMethod -Exactly 1 -ParameterFilter { $Uri -match 'per_page=1' -and $Uri -match 'type=MX' }
        }

        It 'does not create duplicate TXT records when the desired record already exists' {
            Mock Get-ZedCloudflareDnsRecord {
                [PSCustomObject]@{
                    id      = 'txt-1'
                    name    = 'example.com'
                    type    = 'TXT'
                    content = 'v=spf1 -all'
                }
            }
            Mock Invoke-ZedCloudflareRequest {
                throw 'No write request should be made.'
            }

            $zone = [PSCustomObject]@{
                Id   = 'zone-1'
                Name = 'example.com'
            }
            $record = [PSCustomObject]@{
                Name        = '@'
                Content     = 'v=spf1 -all'
                Ttl         = 3600
                MatchPrefix = 'v=spf1'
            }

            $result = Invoke-ZedCloudflareTxtRecordSync -Context $script:Context -Zone $zone -Record $record

            $result.Action | Should -Be 'Unchanged'
            Should -Invoke Invoke-ZedCloudflareRequest -Exactly 0
        }

        It 'updates an existing TXT record with the same policy prefix' {
            Mock Get-ZedCloudflareDnsRecord {
                [PSCustomObject]@{
                    id      = 'txt-1'
                    name    = 'example.com'
                    type    = 'TXT'
                    content = 'v=spf1 include:_spf.example.com -all'
                }
            }
            Mock Invoke-ZedCloudflareRequest {
                [PSCustomObject]@{
                    result = [PSCustomObject]@{
                        id = 'txt-1'
                    }
                }
            } -ParameterFilter { $Method -eq 'Put' }

            $zone = [PSCustomObject]@{
                Id   = 'zone-1'
                Name = 'example.com'
            }
            $record = [PSCustomObject]@{
                Name        = '@'
                Content     = 'v=spf1 -all'
                Ttl         = 3600
                MatchPrefix = 'v=spf1'
            }

            $result = Invoke-ZedCloudflareTxtRecordSync -Context $script:Context -Zone $zone -Record $record

            $result.Action | Should -Be 'Updated'
            Should -Invoke Invoke-ZedCloudflareRequest -Exactly 1 -ParameterFilter { $Method -eq 'Put' }
        }

        It 'creates a TXT record when no matching record exists' {
            Mock Get-ZedCloudflareDnsRecord { @() }
            Mock Invoke-ZedCloudflareRequest {
                [PSCustomObject]@{
                    result = [PSCustomObject]@{
                        id = 'txt-2'
                    }
                }
            } -ParameterFilter { $Method -eq 'Post' }

            $zone = [PSCustomObject]@{
                Id   = 'zone-1'
                Name = 'example.com'
            }
            $record = [PSCustomObject]@{
                Name        = '_dmarc'
                Content     = 'v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s'
                Ttl         = 3600
                MatchPrefix = 'v=DMARC1'
            }

            $result = Invoke-ZedCloudflareTxtRecordSync -Context $script:Context -Zone $zone -Record $record

            $result.Action | Should -Be 'Created'
            Should -Invoke Invoke-ZedCloudflareRequest -Exactly 1 -ParameterFilter { $Method -eq 'Post' }
        }
    }
}
