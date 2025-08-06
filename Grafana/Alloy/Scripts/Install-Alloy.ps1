<#
.DESCRIPTION
    Installs the Cortex Gateway.

.EXAMPLE
    .\Install-Alloy.ps1

.NOTES
    Version : 1.0.0.25340
#>

Import-Module "$PSScriptRoot\Install-Alloy.psm1"

Install-RSAT

Import-Module ActiveDirectory
Set-Location $PSScriptRoot

$ServiceUser = Get-ServiceUser

Set-LocalSecurityPolicy -Username $($ServiceUser.UserName)

Set-RegistryPermissions -Username $($ServiceUser.UserName)

Set-BearerToken -Username $($ServiceUser.UserName)

Install-Alloy -ServiceUser $ServiceUser