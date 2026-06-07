function Write-AgentLog {
    param(
        [Parameter(Mandatory = $true)][string]$InstallDir,
        [Parameter(Mandatory = $true)][string]$ClientId,
        [Parameter(Mandatory = $true)][string]$Message
    )

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $logFile = Join-Path $InstallDir "agent-$ClientId.log"
    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Write-Host $line
    try {
        Add-Content -LiteralPath $logFile -Value $line -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Warning "Could not write log file ${logFile}: $($_.Exception.Message)"
    }
}

function Uninstall-Agent {
    param(
        [Parameter(Mandatory = $true)][string]$ClientId
    )

    $installDir = Join-Path $env:ProgramData "lighthouse-firewall-auto-allow"
    $runner = Join-Path $installDir "report-$ClientId.ps1"
    $taskName = "LighthouseFirewallAutoAllow-$ClientId"
    Write-AgentLog -InstallDir $installDir -ClientId $ClientId -Message "Uninstalling $ClientId"
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $runner -Force -ErrorAction SilentlyContinue
    Write-AgentLog -InstallDir $installDir -ClientId $ClientId -Message "Uninstalled $ClientId"
}

function Install-Agent {
    param(
        [Parameter(Mandatory = $true)][string]$ClientId,
        [Parameter(Mandatory = $true)][string]$Token,
        [Parameter(Mandatory = $true)][string]$ServerUrl,
        [Parameter(Mandatory = $true)][int]$FrequencySeconds,
        [Parameter(Mandatory = $true)][ValidateSet("ipv4", "ipv6", "all")][string]$IpMode
    )

    $ErrorActionPreference = "Stop"
    $installDir = Join-Path $env:ProgramData "lighthouse-firewall-auto-allow"
    $runner = Join-Path $installDir "report-$ClientId.ps1"
    $taskName = "LighthouseFirewallAutoAllow-$ClientId"
    $FrequencySeconds = [Math]::Max($FrequencySeconds, 1)

    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    Write-AgentLog -InstallDir $installDir -ClientId $ClientId -Message "Installing $ClientId"

@"
`$ErrorActionPreference = "Stop"
`$ClientId = "$ClientId"
`$Token = "$Token"
`$ReportUrl = "$($ServerUrl.TrimEnd('/'))/api/v1/report/$ClientId"
`$IpMode = "$IpMode"
`$FrequencySeconds = $FrequencySeconds
`$TaskName = "$taskName"
`$Runner = `$PSCommandPath
`$LogFile = Join-Path (Split-Path -Parent `$Runner) "agent-$ClientId.log"

function Write-AgentLog {
    param([string]`$Message)
    `$line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), `$Message
    try {
        Add-Content -LiteralPath `$LogFile -Value `$line -Encoding UTF8 -ErrorAction Stop
    } catch {
    }
}

function Uninstall-CurrentAgent {
    Write-AgentLog "Uninstalling $ClientId"
    Unregister-ScheduledTask -TaskName `$TaskName -Confirm:`$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath `$Runner -Force -ErrorAction SilentlyContinue
}

function Get-PublicIp {
    param([string]`$Url)

    try {
        `$value = (& curl -fsSL --max-time 10 `$Url 2>`$null)
        if (`$LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace(`$value)) {
            return `$value.Trim()
        }
        Write-AgentLog "curl failed for `$Url with exit code `$LASTEXITCODE"
    } catch {
        Write-AgentLog "curl failed for `$(`$Url): `$(`$_.Exception.Message)"
    }

    try {
        `$value = (Invoke-RestMethod -Uri `$Url -TimeoutSec 10).ToString()
        if (-not [string]::IsNullOrWhiteSpace(`$value)) {
            return `$value.Trim()
        }
        Write-AgentLog "Invoke-RestMethod returned empty value for `$Url"
    } catch {
        Write-AgentLog "Invoke-RestMethod failed for `$(`$Url): `$(`$_.Exception.Message)"
    }

    return `$null
}

function Invoke-AgentReport {
    Write-AgentLog "Reporting $ClientId"
    `$ipv4 = `$null
    `$ipv6 = `$null
    if (`$IpMode -eq "ipv4" -or `$IpMode -eq "all") {
        `$ipv4 = Get-PublicIp -Url "https://ip4.blsy.team"
    }
    if (`$IpMode -eq "ipv6" -or `$IpMode -eq "all") {
        `$ipv6 = Get-PublicIp -Url "https://ip6.blsy.team"
    }

    `$body = @{
        hostname = `$env:COMPUTERNAME
        ipv4 = `$ipv4
        ipv6 = `$ipv6
        agent_version = "0.1.0"
    } | ConvertTo-Json

    try {
        Invoke-RestMethod -Method Post -Uri `$ReportUrl -Headers @{ Authorization = "Bearer `$Token" } -ContentType "application/json" -Body `$body | Out-Null
        Write-AgentLog "Report succeeded"
    } catch {
        `$statusCode = `$null
        if (`$_.Exception.Response -ne `$null) {
            `$statusCode = `$_.Exception.Response.StatusCode.value__
        }
        if (`$statusCode -eq 410) {
            Write-AgentLog "Server returned 410; uninstalling"
            Uninstall-CurrentAgent
            exit 0
        }
        Write-AgentLog "Report failed: `$(`$_.Exception.Message)"
        throw
    }
}

if (`$args.Count -gt 0 -and `$args[0] -eq "uninstall") {
    Uninstall-CurrentAgent
    exit 0
}

if (`$args.Count -gt 0 -and `$args[0] -eq "loop") {
    while (`$true) {
        try {
            Invoke-AgentReport
        } catch {
            Write-AgentLog "Loop iteration failed: `$(`$_.Exception.Message)"
        }
        Start-Sleep -Seconds `$FrequencySeconds
    }
}

Invoke-AgentReport
"@ | Set-Content -LiteralPath $runner -Encoding UTF8

    if ($FrequencySeconds -lt 60) {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$runner`" loop"
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force -ErrorAction Stop | Out-Null
        Write-AgentLog -InstallDir $installDir -ClientId $ClientId -Message "Registered startup loop task $taskName; interval ${FrequencySeconds}s"
    } else {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$runner`""
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(30) -RepetitionInterval (New-TimeSpan -Seconds $FrequencySeconds)
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force -ErrorAction Stop | Out-Null
        Write-AgentLog -InstallDir $installDir -ClientId $ClientId -Message "Registered scheduled task $taskName; interval ${FrequencySeconds}s"
    }

    Write-AgentLog -InstallDir $installDir -ClientId $ClientId -Message "Running first report"
    powershell.exe -ExecutionPolicy Bypass -File $runner
    if ($LASTEXITCODE -ne 0) {
        Write-AgentLog -InstallDir $installDir -ClientId $ClientId -Message "First report failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }
    Write-AgentLog -InstallDir $installDir -ClientId $ClientId -Message "Install complete"
}
