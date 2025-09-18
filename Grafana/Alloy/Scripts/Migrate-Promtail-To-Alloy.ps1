<#
.DESCRIPTION
    Migrates Promtail to Grafana Alloy.

.EXAMPLE
    .\Migrate-Promtail-To-Alloy.ps1 -PromtailConfig "C:\ProgramData\Cortex\Observability\Promtail\promtail-local-config.yaml"

.NOTES
    Version : 1.0.0.25410
#>

param(
    [string]$PromtailConfig
)

Import-Module "$PSScriptRoot\Install-Alloy.psm1"
Import-Module "$PSScriptRoot\Migrate-Promtail-To-Alloy.psm1"

Install-RSAT

Import-Module ActiveDirectory
Set-Location $PSScriptRoot

$ServiceUser = Get-ServiceUser

Set-LocalSecurityPolicy -Username $($ServiceUser.UserName)
Set-RegistryPermissions -Username $($ServiceUser.UserName)

Install-Alloy -ServiceUser $ServiceUser
Wait-ForAlloyReady -ServiceName "Alloy" -TimeoutSeconds 20
Migrate-Promtail-To-Alloy -PromtailConfig $PromtailConfig

Set-BearerToken-OnMigration -Username $($ServiceUser.UserName)

Restart-Alloy
