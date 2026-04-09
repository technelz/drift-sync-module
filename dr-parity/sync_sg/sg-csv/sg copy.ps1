param(
    [Parameter(Mandatory = $true)]
    [string]$CsvPath,

    [Parameter(Mandatory = $true)]
    [string]$TargetVpcId,

    [Parameter(Mandatory = $true)]
    [string]$Region,

    [Parameter(Mandatory = $true)]
    [string]$AwsProfile,

    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false
$env:AWS_PAGER = ""
$scriptStart = Get-Date

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$ts] $Message"
}

function Invoke-AwsCli {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $cleanArgs = $Arguments | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    if (-not $cleanArgs -or $cleanArgs.Count -eq 0) {
        throw "Invoke-AwsCli received no valid arguments."
    }

    $fullArgs = @("--no-cli-pager", "--profile", $AwsProfile, "--region", $Region) + $cleanArgs
    $cmdText = "aws $($fullArgs -join ' ')"
    Write-Log "RUNNING: $cmdText"

    if ($DryRun) {
        Write-Log "[DRYRUN] command skipped"
        return $null
    }

    $outputLines = & aws @fullArgs 2>&1 | ForEach-Object { $_.ToString() }
    $exitCode = $LASTEXITCODE

    Write-Log "EXIT CODE: $exitCode"
    if ($outputLines) {
        Write-Log "AWS OUTPUT:"
        $outputLines | ForEach-Object { Write-Host $_ }
    }

    if ($exitCode -ne 0) {
        throw "AWS CLI failed (exit $exitCode): $cmdText"
    }

    return ($outputLines -join "`n").Trim()
}

function Normalize-Direction {
    param([string]$TypeValue)

    if ([string]::IsNullOrWhiteSpace($TypeValue)) {
        throw "Row has empty Type/Direction value."
    }

    $t = $TypeValue.Trim().ToLowerInvariant()
    if ($t -match "inbound|ingress") { return "ingress" }
    if ($t -match "outbound|egress") { return "egress" }

    throw "Unsupported Type/Direction value: '$TypeValue'"
}

function Normalize-Protocol {
    param([string]$ProtocolValue)

    if ([string]::IsNullOrWhiteSpace($ProtocolValue)) {
        return "-1"
    }

    return "$ProtocolValue".Trim().Trim("'").Trim('"')
}

function Clean-IpRange {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    $clean = $Value.Trim()
    if ($clean -match '^([^\s\(]+)') {
        return $matches[1]
    }

    return $clean
}

function Extract-IdsFromCell {
    param(
        [string]$Value,
        [Parameter(Mandatory = $true)]
        [string]$Pattern
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return @()
    }

    $matches = [regex]::Matches($Value, $Pattern)
    if (-not $matches -or $matches.Count -eq 0) {
        return @()
    }

    return $matches | ForEach-Object { $_.Value } | Select-Object -Unique
}

function Get-ExistingSecurityGroupByName {
    param([string]$GroupName)

    $args = @(
        "ec2", "describe-security-groups",
        "--filters",
        "Name=vpc-id,Values=$TargetVpcId",
        "Name=group-name,Values=$GroupName",
        "--query", "SecurityGroups[0].GroupId",
        "--output", "text"
    )

    $result = Invoke-AwsCli -Arguments $args
    if ($DryRun) { return $null }
    if (-not $result) { return $null }

    $groupId = ($result | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($groupId) -or $groupId -eq "None") {
        return $null
    }

    return $groupId
}

function Get-TargetDefaultSecurityGroupId {
    $args = @(
        "ec2", "describe-security-groups",
        "--filters",
        "Name=vpc-id,Values=$TargetVpcId",
        "Name=group-name,Values=default",
        "--query", "SecurityGroups[0].GroupId",
        "--output", "text"
    )

    $result = Invoke-AwsCli -Arguments $args
    if ($DryRun) { return "sg-dryrun-default" }

    $groupId = ($result | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($groupId) -or $groupId -eq "None") {
        throw "Could not find target default SG in $TargetVpcId"
    }

    return $groupId
}

function Get-TagListFromRow {
    param([pscustomobject]$Row)

    $tagList = New-Object System.Collections.Generic.List[object]

    if ($Row.PSObject.Properties.Name -contains "TagsJson") {
        if (-not [string]::IsNullOrWhiteSpace($Row.TagsJson)) {
            try {
                $parsed = $Row.TagsJson | ConvertFrom-Json -ErrorAction Stop
                if ($parsed -is [System.Collections.IEnumerable] -and -not ($parsed -is [string])) {
                    foreach ($item in $parsed) {
                        if ($null -ne $item.Key -and "$($item.Key)" -notlike "aws:*") {
                            $tagList.Add(@{
                                Key   = "$($item.Key)"
                                Value = "$($item.Value)"
                            })
                        }
                    }
                }
            }
            catch {
                Write-Log "Warning: could not parse TagsJson for group $($Row.GroupName)"
            }
        }
    }

    foreach ($p in $Row.PSObject.Properties) {
        if ($p.Name -like 'Tag:*' -or $p.Name -like 'tag:*') {
            $key = ($p.Name -replace '^[Tt]ag:', '')
            if (-not [string]::IsNullOrWhiteSpace($p.Value) -and $key -notlike "aws:*") {
                $tagList.Add(@{
                    Key   = $key
                    Value = "$($p.Value)"
                })
            }
        }
    }

    return $tagList | Sort-Object Key -Unique
}

function Apply-Tags {
    param(
        [string]$GroupId,
        [object[]]$Tags
    )

    if (-not $Tags -or $Tags.Count -eq 0) { return }

    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("sg-tags-{0}.json" -f ([guid]::NewGuid()))
    try {
        $json = $Tags | ConvertTo-Json -Depth 10 -Compress
        Set-Content -Path $tmp -Value $json -Encoding UTF8

        $args = @(
            "ec2", "create-tags",
            "--resources", $GroupId,
            "--tags", "file://$tmp"
        )
        Invoke-AwsCli -Arguments $args | Out-Null
    }
    finally {
        if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function New-SecurityGroupIfMissing {
    param(
        [string]$GroupName,
        [string]$Description
    )

    $existing = Get-ExistingSecurityGroupByName -GroupName $GroupName
    if ($existing) {
        Write-Log "SKIP existing SG: $GroupName ($existing)"
        return $existing
    }

    $args = @(
        "ec2", "create-security-group",
        "--group-name", $GroupName,
        "--description", $Description,
        "--vpc-id", $TargetVpcId,
        "--query", "GroupId",
        "--output", "text"
    )

    $groupId = Invoke-AwsCli -Arguments $args

    if ($DryRun) {
        return "sg-dryrun-placeholder-$($GroupName -replace '[^a-zA-Z0-9-]', '-')"
    }

    $groupId = ($groupId | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($groupId) -or $groupId -eq "None") {
        throw "Failed creating SG: $GroupName"
    }

    return $groupId
}

function Test-RuleRowUseful {
    param([pscustomobject]$Row)

    $hasProtocol = -not [string]::IsNullOrWhiteSpace($Row.IpProtocol)
    $hasIpv4 = -not [string]::IsNullOrWhiteSpace((Clean-IpRange -Value $Row.IpRanges))
    $hasIpv6 = $false
    if ($Row.PSObject.Properties.Name -contains "Ipv6Ranges") {
        $hasIpv6 = -not [string]::IsNullOrWhiteSpace((Clean-IpRange -Value $Row.Ipv6Ranges))
    }

    $hasPrefix = $false
    if ($Row.PSObject.Properties.Name -contains "PrefixListIds") {
        $hasPrefix = (Extract-IdsFromCell -Value $Row.PrefixListIds -Pattern 'pl-[0-9a-z]+' ).Count -gt 0
    }

    $hasGroupRefs = $false
    if ($Row.PSObject.Properties.Name -contains "UserIdGroupPairs") {
        $hasGroupRefs = (Extract-IdsFromCell -Value $Row.UserIdGroupPairs -Pattern 'sg-[0-9a-z]+' ).Count -gt 0
    }

    $hasPorts = (-not [string]::IsNullOrWhiteSpace($Row.FromPort)) -or
                (-not [string]::IsNullOrWhiteSpace($Row.ToPort))

    return ($hasProtocol -or $hasIpv4 -or $hasIpv6 -or $hasPrefix -or $hasGroupRefs -or $hasPorts)
}

function Source-Has-AllowAllIpv4Egress {
    param([object[]]$RowsForGroup)

    foreach ($row in $RowsForGroup) {
        if ((Normalize-Direction -TypeValue $row.Type) -ne "egress") { continue }

        $protocol = Normalize-Protocol -ProtocolValue $row.IpProtocol
        $cidr = Clean-IpRange -Value $row.IpRanges

        if ($protocol -eq "-1" -and $cidr -eq "0.0.0.0/0") {
            return $true
        }
    }

    return $false
}

function Revoke-DefaultIpv4EgressIfNeeded {
    param(
        [string]$GroupId,
        [object[]]$RowsForGroup
    )

    $egressRows = $RowsForGroup | Where-Object { (Normalize-Direction -TypeValue $_.Type) -eq "egress" }
    if (-not $egressRows -or $egressRows.Count -eq 0) { return }

    if (Source-Has-AllowAllIpv4Egress -RowsForGroup $RowsForGroup) {
        Write-Log "Leaving default outbound allow-all on $GroupId because source also has it"
        return
    }

    try {
        $args = @(
            "ec2", "revoke-security-group-egress",
            "--group-id", $GroupId,
            "--protocol", "-1",
            "--cidr", "0.0.0.0/0"
        )
        Invoke-AwsCli -Arguments $args | Out-Null
    }
    catch {
        if ($_.Exception.Message -notmatch "InvalidPermission\.NotFound|not found") {
            throw
        }
    }
}

function Add-SimpleRule {
    param(
        [string]$GroupId,
        [string]$Direction,
        [pscustomobject]$Row,
        [hashtable]$Map,
        [string]$SourceGroupId,
        [string]$TargetGroupId
    )

    $protocol = Normalize-Protocol -ProtocolValue $Row.IpProtocol

    $portArg = @()
    if ($protocol -ne "-1" -and
        -not [string]::IsNullOrWhiteSpace($Row.FromPort) -and
        -not [string]::IsNullOrWhiteSpace($Row.ToPort)) {

        if ($Row.FromPort -eq $Row.ToPort) {
            $portArg = @("--port", "$($Row.FromPort)")
        }
        else {
            $portArg = @("--port", "$($Row.FromPort)-$($Row.ToPort)")
        }
    }

    $madeCall = $false

    # IPv4 CIDR
    $cidr = Clean-IpRange -Value $Row.IpRanges
    if (-not [string]::IsNullOrWhiteSpace($cidr)) {
        if ($Direction -eq "ingress") {
            $args = @("ec2","authorize-security-group-ingress","--group-id",$GroupId,"--protocol",$protocol) + $portArg + @("--cidr",$cidr)
        } else {
            if ($protocol -eq "-1" -and $cidr -eq "0.0.0.0/0") {
                Write-Log "Skipping default allow-all IPv4 egress on $GroupId"
                $args = $null
            } else {
                $args = @("ec2","authorize-security-group-egress","--group-id",$GroupId,"--protocol",$protocol) + $portArg + @("--cidr",$cidr)
            }
        }

        if ($args) {
            try {
                Invoke-AwsCli -Arguments $args | Out-Null
            } catch {
                if ($_.Exception.Message -notmatch "Duplicate|InvalidPermission\.Duplicate") { throw }
                Write-Log "Duplicate ${Direction} IPv4 CIDR rule skipped on $GroupId"
            }
            $madeCall = $true
        }
    }

    # IPv6 CIDR
    if ($Row.PSObject.Properties.Name -contains "Ipv6Ranges") {
        $cidr6 = Clean-IpRange -Value $Row.Ipv6Ranges
        if (-not [string]::IsNullOrWhiteSpace($cidr6)) {
            $tmpPerm = @(
                @{
                    IpProtocol = $protocol
                    Ipv6Ranges = @(@{ CidrIpv6 = $cidr6 })
                }
            )

            if ($protocol -ne "-1" -and -not [string]::IsNullOrWhiteSpace($Row.FromPort)) {
                $tmpPerm[0].FromPort = [int]$Row.FromPort
            }
            if ($protocol -ne "-1" -and -not [string]::IsNullOrWhiteSpace($Row.ToPort)) {
                $tmpPerm[0].ToPort = [int]$Row.ToPort
            }

            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("sg-ipv6-{0}.json" -f ([guid]::NewGuid()))
            try {
                $tmpPerm | ConvertTo-Json -Depth 10 -Compress | Set-Content -Path $tmp -Encoding UTF8
                if ($Direction -eq "ingress") {
                    $args = @("ec2","authorize-security-group-ingress","--group-id",$GroupId,"--ip-permissions","file://$tmp")
                } else {
                    $args = @("ec2","authorize-security-group-egress","--group-id",$GroupId,"--ip-permissions","file://$tmp")
                }
                Invoke-AwsCli -Arguments $args | Out-Null
            } catch {
                if ($_.Exception.Message -notmatch "Duplicate|InvalidPermission\.Duplicate") { throw }
                Write-Log "Duplicate ${Direction} IPv6 rule skipped on $GroupId"
            } finally {
                if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
            }
            $madeCall = $true
        }
    }

    # SG references
    if ($Row.PSObject.Properties.Name -contains "UserIdGroupPairs") {
        $sgRefs = Extract-IdsFromCell -Value $Row.UserIdGroupPairs -Pattern 'sg-[0-9a-z]+'
        foreach ($src in $sgRefs) {
            $target = $null

            if ($src -eq $SourceGroupId) {
                $target = $TargetGroupId
            }
            elseif ($Map.ContainsKey($src)) {
                $target = $Map[$src]
            }
            else {
                Write-Log "Skipping unmapped SG reference $src on $GroupId"
                continue
            }

            if ($Direction -eq "ingress") {
                $args = @("ec2","authorize-security-group-ingress","--group-id",$GroupId,"--protocol",$protocol) + $portArg + @("--source-group",$target)
                try {
                    Invoke-AwsCli -Arguments $args | Out-Null
                } catch {
                    if ($_.Exception.Message -notmatch "Duplicate|InvalidPermission\.Duplicate") { throw }
                    Write-Log "Duplicate ingress SG-ref rule skipped on $GroupId"
                }
            }
            else {
                $tmpPerm = @(
                    @{
                        IpProtocol       = $protocol
                        UserIdGroupPairs = @(@{ GroupId = $target })
                    }
                )
                if ($protocol -ne "-1" -and -not [string]::IsNullOrWhiteSpace($Row.FromPort)) { $tmpPerm[0].FromPort = [int]$Row.FromPort }
                if ($protocol -ne "-1" -and -not [string]::IsNullOrWhiteSpace($Row.ToPort))   { $tmpPerm[0].ToPort   = [int]$Row.ToPort }

                $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("sg-egress-group-{0}.json" -f ([guid]::NewGuid()))
                try {
                    $tmpPerm | ConvertTo-Json -Depth 10 -Compress | Set-Content -Path $tmp -Encoding UTF8
                    $args = @("ec2","authorize-security-group-egress","--group-id",$GroupId,"--ip-permissions","file://$tmp")
                    Invoke-AwsCli -Arguments $args | Out-Null
                } catch {
                    if ($_.Exception.Message -notmatch "Duplicate|InvalidPermission\.Duplicate") { throw }
                    Write-Log "Duplicate egress SG-ref rule skipped on $GroupId"
                } finally {
                    if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
                }
            }

            $madeCall = $true
        }
    }

    # Prefix lists
    if ($Row.PSObject.Properties.Name -contains "PrefixListIds") {
        $pls = Extract-IdsFromCell -Value $Row.PrefixListIds -Pattern 'pl-[0-9a-z]+'
        foreach ($plid in $pls) {
            $tmpPerm = @(
                @{
                    IpProtocol    = $protocol
                    PrefixListIds = @(@{ PrefixListId = $plid })
                }
            )

            if ($protocol -ne "-1" -and -not [string]::IsNullOrWhiteSpace($Row.FromPort)) { $tmpPerm[0].FromPort = [int]$Row.FromPort }
            if ($protocol -ne "-1" -and -not [string]::IsNullOrWhiteSpace($Row.ToPort))   { $tmpPerm[0].ToPort   = [int]$Row.ToPort }

            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("sg-prefix-{0}.json" -f ([guid]::NewGuid()))
            try {
                $tmpPerm | ConvertTo-Json -Depth 10 -Compress | Set-Content -Path $tmp -Encoding UTF8
                if ($Direction -eq "ingress") {
                    $args = @("ec2","authorize-security-group-ingress","--group-id",$GroupId,"--ip-permissions","file://$tmp")
                } else {
                    $args = @("ec2","authorize-security-group-egress","--group-id",$GroupId,"--ip-permissions","file://$tmp")
                }
                Invoke-AwsCli -Arguments $args | Out-Null
            } catch {
                if ($_.Exception.Message -notmatch "Duplicate|InvalidPermission\.Duplicate") { throw }
                Write-Log "Duplicate ${Direction} prefix-list rule skipped on $GroupId"
            } finally {
                if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
            }

            $madeCall = $true
        }
    }

    if (-not $madeCall) {
        Write-Log "No applicable ${Direction} rule entries found for $GroupId"
    }
}

# Main
if (-not (Test-Path $CsvPath)) {
    throw "CSV file not found: $CsvPath"
}

$rows = Import-Csv -Path $CsvPath
if (-not $rows -or $rows.Count -eq 0) {
    throw "CSV is empty: $CsvPath"
}

$requiredColumns = @("GroupId", "GroupName", "Type", "IpProtocol", "FromPort", "ToPort", "IpRanges")
foreach ($col in $requiredColumns) {
    if (-not ($rows[0].PSObject.Properties.Name -contains $col)) {
        throw "CSV is missing expected column: $col"
    }
}

Write-Log "Starting CSV-based SG migration"
Write-Log "Target VPC: $TargetVpcId"
Write-Log "Region: $Region"
Write-Log "Profile: $AwsProfile"
Write-Log "CSV: $CsvPath"

$sourceToTargetGroupMap = @{}
$groupBuckets = $rows | Group-Object -Property GroupId | Sort-Object Name
$targetDefaultSgId = Get-TargetDefaultSecurityGroupId

Write-Log "Target default SG: $targetDefaultSgId"
Write-Log "Unique source SG count: $($groupBuckets.Count)"

# Create/map SGs
foreach ($bucket in $groupBuckets) {
    $sourceGroupId = $bucket.Name
    $sampleRow = $bucket.Group | Select-Object -First 1

    if ([string]::IsNullOrWhiteSpace($sampleRow.GroupName)) {
        Write-Log "Skipping source GroupId '$sourceGroupId' because GroupName is empty."
        continue
    }

    $groupName = $sampleRow.GroupName.Trim()

    if ($groupName -eq "default") {
        Write-Log "Mapping source default SG $sourceGroupId to target default SG $targetDefaultSgId"
        $sourceToTargetGroupMap[$sourceGroupId] = $targetDefaultSgId
        continue
    }

    $description = if ($sampleRow.PSObject.Properties.Name -contains "Description" -and -not [string]::IsNullOrWhiteSpace($sampleRow.Description)) {
        "$($sampleRow.Description)"
    } else {
        $groupName
    }

    $targetGroupId = New-SecurityGroupIfMissing -GroupName $groupName -Description $description
    $sourceToTargetGroupMap[$sourceGroupId] = $targetGroupId

    $tags = Get-TagListFromRow -Row $sampleRow
    if ($tags -and $tags.Count -gt 0) {
        Apply-Tags -GroupId $targetGroupId -Tags $tags
    }
}

# Revoke default egress where needed
foreach ($bucket in $groupBuckets) {
    $sourceGroupId = $bucket.Name
    if (-not $sourceToTargetGroupMap.ContainsKey($sourceGroupId)) { continue }

    $targetGroupId = $sourceToTargetGroupMap[$sourceGroupId]
    Revoke-DefaultIpv4EgressIfNeeded -GroupId $targetGroupId -RowsForGroup $bucket.Group
}

# Apply rules
foreach ($bucket in $groupBuckets) {
    $sourceGroupId = $bucket.Name
    if (-not $sourceToTargetGroupMap.ContainsKey($sourceGroupId)) { continue }

    $targetGroupId = $sourceToTargetGroupMap[$sourceGroupId]
    Write-Log "Applying rules for source SG $sourceGroupId -> target SG $targetGroupId"

    foreach ($row in $bucket.Group) {
        if (-not (Test-RuleRowUseful -Row $row)) {
            Write-Log "Skipping non-rule row for source SG $sourceGroupId"
            continue
        }

        $direction = Normalize-Direction -TypeValue $row.Type
        Add-SimpleRule `
            -GroupId $targetGroupId `
            -Direction $direction `
            -Row $row `
            -Map $sourceToTargetGroupMap `
            -SourceGroupId $sourceGroupId `
            -TargetGroupId $targetGroupId
    }
}

$elapsed = (Get-Date) - $scriptStart
Write-Log "Done. Elapsed time: $($elapsed.ToString())"