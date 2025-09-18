<#
.DESCRIPTION
    Functions for migrating Promtail to Grafana Alloy.

.NOTES
    Version : 1.0.0.25410
#>

function Set-BearerTokenFilePath-OnMigration {
    <#
    .DESCRIPTION
        Update config.alloy file to insert bearer_token_file after the LAST 'url =' line
        in the loki.write endpoint block.
    #>
	
    process {
        Write-Output "Updating config.alloy file with bearer token file path"

        $ConfigFile = Join-Path $PSScriptRoot "config.alloy"
        $AuthFile   = Join-Path $PSScriptRoot "auth.secret"

        if (-not (Test-Path -Path $ConfigFile -PathType Leaf)) {
            throw "Config file not found: $ConfigFile"
        }
        if (-not (Test-Path -Path $AuthFile -PathType Leaf)) {
            throw "Auth file not found: $AuthFile"
        }

        $lines = Get-Content -Path $ConfigFile

        # Find the index of the last 'url =' line
        $urlIndex = ($lines | ForEach-Object { $_ } | Select-String -Pattern '^\s*url\s*=' | Select-Object -Last 1).LineNumber
        if (-not $urlIndex) {
            throw "No 'url =' line found in $ConfigFile"
        }

        # Build the new file contents
        $bearerPath = $AuthFile -replace '\\', '/'
        $newLines   = @()
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $newLines += $lines[$i]
            if ($i -eq ($urlIndex - 1)) {
                $newLines += "        bearer_token_file = `"$bearerPath`""
            }
        }

        Set-Content -Path $ConfigFile -Value $newLines -Force

        Write-Output "Updated config.alloy file"
    }
}

function Set-BearerToken-OnMigration {
	<#
    .DESCRIPTION
        Create Bearer Token file and restrict access.

    .PARAMETER Username
        The user name specified for the Grafana Alloy service to run as e.g. "Domain\Username"
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Username
    )

    process {
		Write-Output "Creating bearer token file"
		
		$AuthFile = (Join-Path $PSScriptRoot "auth.secret")
		
		$BearerToken = Read-Host -Prompt "Enter bearer token used by Loki for authentication" -AsSecureString
		
		New-Item $AuthFile -ItemType File -Value ([pscredential]::new('BearerToken',$BearerToken).GetNetworkCredential().Password) -Force | Out-Null
		
		Write-Output "Created bearer token file"

		Set-BearerTokenFilePermissions -AuthFile $AuthFile -Username $Username
	
		Set-BearerTokenFilePath-OnMigration
	}
}

function Migrate-Promtail-To-Alloy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PromtailConfig
    )

    begin {
        $exePath      = Join-Path $env:ProgramFiles 'GrafanaLabs\Alloy\alloy-windows-amd64.exe'
        $outputPath   = Join-Path $env:ProgramData 'Cortex\Observability\Grafana Alloy\config.alloy'
        $outputDir    = Split-Path -Path $outputPath -Parent
		$sourceConfig = (Resolve-Path -Path $PromtailConfig -ErrorAction Stop).Path
    }

    process {
        Write-Output "Starting Promtail to Grafana Alloy config migration"

        if (-not (Test-Path -Path $exePath -PathType Leaf)) {
            throw "Alloy executable not found at '$exePath'. Ensure Alloy is installed before migrating."
        }
        if (-not (Test-Path -Path $sourceConfig -PathType Leaf)) {
            throw "Promtail config not found at '$sourceConfig'."
        }
        if (-not (Test-Path -Path $outputDir -PathType Container)) {
            Write-Output "Creating output directory: $outputDir"
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }

        try {
            & $exePath convert --source-format=promtail --output=$outputPath $sourceConfig
            if ($LASTEXITCODE -ne 0) {
                throw "Conversion failed with exit code $LASTEXITCODE."
            }
        }
        catch {
            throw "Grafana Alloy convert invocation failed: $($_.Exception.Message)"
        }

        if (-not (Test-Path -Path $outputPath -PathType Leaf)) {
            throw "Conversion completed but '$outputPath' was not created."
        }

        Write-Output "Migrated Promtail to Grafana Alloy config"
    }
}


function Restart-Alloy {
    [CmdletBinding()]
    param(
        [string]$ServiceName = 'alloy'
    )
    process {
        Write-Output "Restarting service '$ServiceName'..."
        try {
            Restart-Service -Name $ServiceName -Force -ErrorAction Stop
            Write-Output "Service '$ServiceName' restarted successfully"
        }
        catch {
            throw "Failed to restart service '$ServiceName': $($_.Exception.Message)"
        }
    }
}

function Wait-ForAlloyReady {
    <#
    .SYNOPSIS
        Waits until the Alloy service is running.
    .PARAMETER ServiceName
        Name of the Alloy Windows service. Defaults to 'alloy'.
    .PARAMETER TimeoutSeconds
        Maximum number of seconds to wait. Defaults to 60.
    #>
    [CmdletBinding()]
    param(
        [string]$ServiceName = 'alloy',
        [int]$TimeoutSeconds = 60
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

        if ($service -and $service.Status -eq 'Running') {
            Write-Output "Alloy service is running."
            return
        }

        Start-Sleep -Seconds 1
    }

    throw "Timeout: Alloy service '$ServiceName' not running after $TimeoutSeconds seconds."
}
