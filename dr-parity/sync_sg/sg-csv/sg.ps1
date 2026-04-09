param(
    [Parameter(Mandatory = $true)]
    [string]$JsonPath,

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
        throw "Could not find the target VPC default SG in $TargetVpcId"
    }

    return $groupId
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

function Apply-Tags {
    param(
        [string]$GroupId,
        [object[]]$Tags
    )

    if (-not $Tags -or $Tags.Count -eq 0) { return }

    $filteredTags = @()
    foreach ($tag in $Tags) {
        if ($null -eq $tag.Key) { continue }
        if ("$($tag.Key)" -like "aws:*") { continue }

        $filteredTags += @{
            Key   = "$($tag.Key)"
            Value = "$($tag.Value)"
        }
    }

    if ($filteredTags.Count -eq 0) { return }

    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("sg-tags-{0}.json" -f ([guid]::NewGuid()))
    try {
        $json = $filteredTags | ConvertTo-Json -Depth 10 -Compress
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

function Source-Has-AllowAllIpv4Egress {
    param([object[]]$Rules)

    foreach ($r in $Rules) {
        if ("$($r.IpProtocol)" -eq "-1" -and $r.IpRanges) {
            foreach ($ip in $r.IpRanges) {
                if ("$($ip.CidrIp)" -eq "0.0.0.0/0") {
                    return $true
                }
            }
        }
    }

    return $false
}

function Revoke-DefaultIpv4EgressIfNeeded {
    param(
        [string]$GroupId,
        [object[]]$SourceEgressRules
    )

    if (-not $SourceEgressRules -or $SourceEgressRules.Count -eq 0) { return }

    if (Source-Has-AllowAllIpv4Egress -Rules $SourceEgressRules) {
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
        [object]$Rule,
        [hashtable]$Map,
        [string]$SourceGroupId,
        [string]$TargetGroupId
    )

    $protocol = "$($Rule.IpProtocol)"

    $portArg = @()
    if ($protocol -ne "-1" -and $null -ne $Rule.FromPort -and $null -ne $Rule.ToPort) {
        if ($Rule.FromPort -eq $Rule.ToPort) {
            $portArg = @("--port", "$($Rule.FromPort)")
        } else {
            $portArg = @("--port", "$($Rule.FromPort)-$($Rule.ToPort)")
        }
    }

    $madeCall = $false

    foreach ($ip in @($Rule.IpRanges)) {
        if ($null -eq $ip) { continue }
        $cidr = "$($ip.CidrIp)"
        if ([string]::IsNullOrWhiteSpace($cidr)) { continue }

        if ($Direction -eq "ingress") {
            $args = @("ec2","authorize-security-group-ingress","--group-id",$GroupId,"--protocol",$protocol) + $portArg + @("--cidr",$cidr)
        } else {
            if ($protocol -eq "-1" -and $cidr -eq "0.0.0.0/0") {
                Write-Log "Skipping default allow-all IPv4 egress on $GroupId"
                continue
            }
            $args = @("ec2","authorize-security-group-egress","--group-id",$GroupId,"--protocol",$protocol) + $portArg + @("--cidr",$cidr)
        }

        try {
            Invoke-AwsCli -Arguments $args | Out-Null
        } catch {
            if ($_.Exception.Message -notmatch "Duplicate|InvalidPermission\.Duplicate") { throw }
            Write-Log "Duplicate ${Direction} CIDR rule skipped on $GroupId"
        }
        $madeCall = $true
    }

    foreach ($ipv6 in @($Rule.Ipv6Ranges)) {
        if ($null -eq $ipv6) { continue }
        $cidr6 = "$($ipv6.CidrIpv6)"
        if ([string]::IsNullOrWhiteSpace($cidr6)) { continue }

        if ($Direction -eq "ingress") {
            $args = @("ec2","authorize-security-group-ingress","--group-id",$GroupId,"--protocol",$protocol) + $portArg + @("--cidr",$cidr6)
        } else {
            $args = @("ec2","authorize-security-group-egress","--group-id",$GroupId,"--protocol",$protocol) + $portArg + @("--cidr",$cidr6)
        }

        try {
            Invoke-AwsCli -Arguments $args | Out-Null
        } catch {
            if ($_.Exception.Message -notmatch "Duplicate|InvalidPermission\.Duplicate") { throw }
            Write-Log "Duplicate ${Direction} IPv6 rule skipped on $GroupId"
        }
        $madeCall = $true
    }

    foreach ($sg in @($Rule.UserIdGroupPairs)) {
        if ($null -eq $sg) { continue }
        $src = "$($sg.GroupId)"
        if ([string]::IsNullOrWhiteSpace($src)) { continue }

        if ($src -eq $SourceGroupId) {
            $target = $TargetGroupId
        } elseif ($Map.ContainsKey($src)) {
            $target = $Map[$src]
        } else {
            Write-Log "Skipping unmapped SG reference $src on $GroupId"
            continue
        }

        if ($Direction -eq "ingress") {
            $args = @("ec2","authorize-security-group-ingress","--group-id",$GroupId,"--protocol",$protocol) + $portArg + @("--source-group",$target)
        } else {
            $tmpPerm = @(
                @{
                    IpProtocol       = $protocol
                    UserIdGroupPairs = @(@{ GroupId = $target })
                }
            )
            if ($protocol -ne "-1" -and $null -ne $Rule.FromPort) { $tmpPerm[0].FromPort = [int]$Rule.FromPort }
            if ($protocol -ne "-1" -and $null -ne $Rule.ToPort)   { $tmpPerm[0].ToPort   = [int]$Rule.ToPort }

            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("sg-egress-group-{0}.json" -f ([guid]::NewGuid()))
            try {
                $tmpPerm | ConvertTo-Json -Depth 10 -Compress | Set-Content -Path $tmp -Encoding UTF8
                $args = @("ec2","authorize-security-group-egress","--group-id",$GroupId,"--ip-permissions","file://$tmp")
                Invoke-AwsCli -Arguments $args | Out-Null
            } catch {
                if ($_.Exception.Message -notmatch "Duplicate|InvalidPermission\.Duplicate") { throw }
                Write-Log "Duplicate ${Direction} SG-ref rule skipped on $GroupId"
            } finally {
                if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
            }
            $madeCall = $true
            continue
        }

        try {
            Invoke-AwsCli -Arguments $args | Out-Null
        } catch {
            if ($_.Exception.Message -notmatch "Duplicate|InvalidPermission\.Duplicate") { throw }
            Write-Log "Duplicate ${Direction} SG-ref rule skipped on $GroupId"
        }
        $madeCall = $true
    }

    foreach ($pl in @($Rule.PrefixListIds)) {
        if ($null -eq $pl) { continue }
        $plid = "$($pl.PrefixListId)"
        if ([string]::IsNullOrWhiteSpace($plid)) { continue }

        $tmpPerm = @(
            @{
                IpProtocol    = $protocol
                PrefixListIds = @(@{ PrefixListId = $plid })
            }
        )
        if ($protocol -ne "-1" -and $null -ne $Rule.FromPort) { $tmpPerm[0].FromPort = [int]$Rule.FromPort }
        if ($protocol -ne "-1" -and $null -ne $Rule.ToPort)   { $tmpPerm[0].ToPort   = [int]$Rule.ToPort }

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

    if (-not $madeCall) {
        Write-Log "No applicable ${Direction} rule entries found for $GroupId"
    }
}

function Apply-RuleSet {
    param(
        [string]$TargetGroupId,
        [string]$CurrentSourceGroupId,
        [string]$Direction,
        [object[]]$Rules,
        [hashtable]$SourceToTargetGroupMap
    )

    if (-not $Rules -or $Rules.Count -eq 0) { return }

    Write-Log "Preparing ${Direction} rules for $TargetGroupId"
    Write-Log "Source rule count for ${Direction}: $($Rules.Count)"

    foreach ($rule in $Rules) {
        Add-SimpleRule `
            -GroupId $TargetGroupId `
            -Direction $Direction `
            -Rule $rule `
            -Map $SourceToTargetGroupMap `
            -SourceGroupId $CurrentSourceGroupId `
            -TargetGroupId $TargetGroupId
    }
}

if (-not (Test-Path $JsonPath)) {
    throw "JSON file not found: $JsonPath"
}

$raw = Get-Content -Path $JsonPath -Raw
$data = $raw | ConvertFrom-Json

if ($null -eq $data.SecurityGroups -or $data.SecurityGroups.Count -eq 0) {
    throw "No SecurityGroups found in JSON: $JsonPath"
}

Write-Log "Starting JSON-based SG migration"
Write-Log "Target VPC: $TargetVpcId"
Write-Log "Region: $Region"
Write-Log "Profile: $AwsProfile"
Write-Log "JSON: $JsonPath"

$sourceToTargetGroupMap = @{}
$targetDefaultSgId = Get-TargetDefaultSecurityGroupId
Write-Log "Target default SG: $targetDefaultSgId"

foreach ($sg in $data.SecurityGroups) {
    $groupName = "$($sg.GroupName)"
    $sourceGroupId = "$($sg.GroupId)"
    $description = "$($sg.Description)"

    if ($groupName -eq "default") {
        $sourceToTargetGroupMap[$sourceGroupId] = $targetDefaultSgId
        Write-Log "Mapped source default SG $sourceGroupId to target default SG $targetDefaultSgId"
        continue
    }

    $targetGroupId = New-SecurityGroupIfMissing -GroupName $groupName -Description $description
    $sourceToTargetGroupMap[$sourceGroupId] = $targetGroupId
    Apply-Tags -GroupId $targetGroupId -Tags $sg.Tags
}

foreach ($sg in $data.SecurityGroups) {
    $sourceGroupId = "$($sg.GroupId)"
    if (-not $sourceToTargetGroupMap.ContainsKey($sourceGroupId)) { continue }

    $targetGroupId = $sourceToTargetGroupMap[$sourceGroupId]

    Revoke-DefaultIpv4EgressIfNeeded -GroupId $targetGroupId -SourceEgressRules $sg.IpPermissionsEgress

    Apply-RuleSet `
        -TargetGroupId $targetGroupId `
        -CurrentSourceGroupId $sourceGroupId `
        -Direction "ingress" `
        -Rules $sg.IpPermissions `
        -SourceToTargetGroupMap $sourceToTargetGroupMap

    Apply-RuleSet `
        -TargetGroupId $targetGroupId `
        -CurrentSourceGroupId $sourceGroupId `
        -Direction "egress" `
        -Rules $sg.IpPermissionsEgress `
        -SourceToTargetGroupMap $sourceToTargetGroupMap
}

$elapsed = (Get-Date) - $scriptStart
Write-Log "Done. Elapsed time: $($elapsed.ToString())"