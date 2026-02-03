<#
.DESCRIPTION
    Functions for installing Grafana Alloy.

.NOTES
    Version : 1.0.1.26130
#>

#region Internal Functions
function Export-LocalSecurityPolicy {
    <#
    .DESCRIPTION
        Exports the current local security policy.
    #>

    process {
        # Export current Local Security Policy configuration
        $secEditConfigurationExportFile = Get-TempFileName
        secedit.exe /export /cfg "$($secEditConfigurationExportFile)" /quiet

        if ($? -eq $false) {
            exit 1
        }

        $secEditConfigurationExportFile
    }
}

function Get-TempFileName {
    <#
    .DESCRIPTION
        Returns a temporary file name.
    #>

    process {
        [System.IO.Path]::GetTempFileName()
    }
}

function Get-TempPath {
    <#
    .DESCRIPTION
        Returns the location for a temporary file to be created.
    #>

    process {
        [System.IO.Path]::GetTempPath()
    }
}

function Set-BearerTokenFilePath {
	<#
    .DESCRIPTION
        Update config.alloy file to contain correct path to bearer token file.
    #>
	
	process {
		Write-Output "Updating config.alloy file with correct bearer token file path"
		$ConfigFile = (Join-Path $PSScriptRoot "config.alloy")
		
		((Get-Content -path $ConfigFile -Raw) -replace '<Config File Path>', ($PSScriptRoot -replace "\\", "/")) | Set-Content -Path $ConfigFile
		
		Write-Output "Updated config.alloy file"
	}
}

function Set-BearerTokenFilePermissions {
	<#
    .DESCRIPTION
        Update bearer token file permissions to restrict access.

    .PARAMETER AuthFile
        The file name and path containing the bearer token.

    .PARAMETER Username
        User that Grafana Alloy will run as.
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $AuthFile,
		
        [Parameter(Mandatory = $true)]
        [string]
        $Username
    )

    process {
	
		Write-Output "Updating bearer token file permissions to restrict access"
		# Get current ACL
		$acl = Get-Acl $AuthFile
		
		# Define permission rules
		$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "Allow")
		$userRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Username, "Read", "Allow")
		
		# Remove inherited permissions (to restrict access only to defined users)
		$acl.SetAccessRuleProtection($true, $false)

		# Add the new rules
		$acl.SetAccessRule($adminRule)
		$acl.AddAccessRule($userRule)
		
		# Apply the ACL to the file
		Set-Acl -Path $AuthFile -AclObject $acl
		
		Write-Output "Updated bearer token file permissions"
	}
}

function Set-RegistryPermissions {
    <#
    .DESCRIPTION
        Sets registry permissions for the Grafana Alloy username.

    .PARAMETER Username
        User that Grafana Alloy will run as.
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Username
    )

    process {
		Write-Output "Granting registry permissions to $Username"
		$acl = Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application"
		$rule = New-Object System.Security.AccessControl.RegistryAccessRule($Username,"FullControl","ContainerInherit,ObjectInherit","None","Allow")
		$acl.AddAccessRule($rule)
		$acl |Set-Acl
		Write-Output "Granted registry permissions"
	}
}

function Test-ServiceUser {
    <#
    .DESCRIPTION
        Tests the credentials specified for the Grafana Alloy service user.

    .PARAMETER ServiceUser
        Domain User specified for Grafana Alloy to as.
		
    #>
	
	param(
		[Parameter(Mandatory = $false)]
		[PSCredential]
		[System.Management.Automation.PSCredential]
		$ServiceUser
	)
	
    process {
		Add-Type -AssemblyName System.DirectoryServices.AccountManagement

		$contextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
		$domainName, $Username = $ServiceUser.Username -split '\\'
		$password = $ServiceUser.GetNetworkCredential().Password
				
		$principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($contextType, $domainName)
		
		$isValid = $principalContext.ValidateCredentials($userName, $password)
		$isValid
	}
}

function Update-LocalSecurityPolicy {
    <#
    .DESCRIPTION
        Updates the local security policy.

    .PARAMETER NewSeServiceLogonRight
        List of users/groups that should have the Logon as a Service right
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $NewSeServiceLogonRight
    )

    process {
        $tmpPath = Get-TempPath

        # Generate security policy template
        $TemplateFile = "$tmpPath\CortexPolicy.inf"
        $stream = [System.IO.StreamWriter] $TemplateFile
        $stream.WriteLine("[Unicode]")
        $stream.WriteLine("Unicode=yes")
        $stream.WriteLine("[Version]")
        $stream.WriteLine("signature=`"`$CHICAGO`$`"")
        $stream.WriteLine("Revision=1")
        $stream.WriteLine("[Privilege Rights]")
        $stream.WriteLine("SeServiceLogonRight = $NewSeServiceLogonRight")
        $stream.close()

        secedit.exe /configure /db "$tmpPath\temp.sdb" /cfg "$TemplateFile" /areas USER_RIGHTS /quiet

		$files = "$tmpPath\temp.sdb", "$tmpPath\temp.jfm", "$TemplateFile"
		
        Foreach ($file in $files) {
			If (Test-Path $file) {
				Remove-Item $file -Force
			}
		}
    }
}

#endregion Internal Functions

#region Public Functions
function Get-ServiceUser {
    <#
    .DESCRIPTION
        Prompts for credentials for the Grafana Alloy service user and verfies they are valid.
    #>

    process {
		$ServiceUser = $Host.UI.PromptForCredential("Service User Details", "Please enter the username and password for the user that will run Grafana Alloy.", "", "Domain")
		$Verified = Test-ServiceUser -ServiceUser $ServiceUser
		
		if ($Verified -eq $false) {
			Write-Error "Verification of credentials for ($($ServiceUser.UserName)) has failed."
			exit 1
		}
		else {
			$ServiceUser
		}
	}
}

function Install-Alloy {
    <#
    .DESCRIPTION
        Installs Grafana Alloy service.
		
    .PARAMETER ServiceUser
        Domain User specified for Grafana Alloy to as.
    #>

	param(
		[Parameter(Mandatory = $false)]
		[PSCredential]
		[System.Management.Automation.PSCredential]
		$ServiceUser
	)
	
    process {
		Write-Output "Installing Grafana Alloy"
		
		.\alloy-installer-windows-amd64.exe /S /CONFIG=(Join-Path $PSScriptRoot "config.alloy") /USERNAME="$($ServiceUser.UserName)" /PASSWORD="$($ServiceUser.GetNetworkCredential().Password)"
		
		Write-Output "Installed Grafana Alloy"
	}
}

function Install-RSAT {
    <#
    .DESCRIPTION
        Installs required Windows Features.
    #>
	
    process {
        $FeatureName = "RSAT-AD-PowerShell"

		Write-Output "Checking required Windows Features are installed"
		
        # If the windows feature isn't currently installed then attempt to install them
		if (Get-WindowsFeature -Name $FeatureName | Where-Object { $_.Installed -match "False" }) {
			Write-Output "Installing $FeatureName"

			Install-WindowsFeature -Name $FeatureName -ErrorVariable errors | Out-Null

			# Check if there are any errors
			if ($errors -ne $null) {
				Write-Output "$error[0]"
				exit 1
			}

			Write-Output "Installed $FeatureName"
		}
		else {
			Write-Output "$FeatureName already installed"
		}
    }
}

function Set-BearerToken {
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
	
		Set-BearerTokenFilePath
	}
}

function Set-LocalSecurityPolicy {
    <#
    .DESCRIPTION
        Checks the local security policy configured for the specified user and updates if necessary.

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
        Write-Output "Verifying Local Security Policy for $Username"
        $UserSID = (New-Object System.Security.Principal.NTAccount($Username.substring($Username.IndexOf("\") + 1))).Translate([System.Security.Principal.SecurityIdentifier]).Value

        $secEditConfigurationExport = Export-LocalSecurityPolicy
		
        $UpdateSecPolRequired = $false
        $NewSeServiceLogonRight = $null

        Get-Content -Path $secEditConfigurationExport | Foreach-Object {
            if ( $_ -like "SeServiceLogonRight*") {
                $currentSeServiceLogonRight = try { $_.split("=", [System.StringSplitOptions]::RemoveEmptyEntries)[1].Trim() } catch { $null }
			    $rowValues = try { $currentSeServiceLogonRight.split(",", [System.StringSplitOptions]::RemoveEmptyEntries) } catch { $null }
			    if ($rowValues.contains("*$($UserSID)")) {
				    $NewSeServiceLogonRight = $currentSeServiceLogonRight
			    }
			    else {
				    # Log on as service policy needs user adding
				    Write-Output "Adding $userSID to 'Log on as a service' local security policy"
				    $NewSeServiceLogonRight = "*$($UserSID),$($currentSeServiceLogonRight)"
				    $UpdateSecPolRequired = $true
			    }
            }
        }

        if (!($NewSeServiceLogonRight)) {
            # Log on as a service policy was blank and needs user adding
            Write-Output "Adding $UserSID to 'Log on as a service' Local Security Policy"
            $NewSeServiceLogonRight = "*$($UserSID)"
            $UpdateSecPolRequired = $true
        }

        # Update User Rights Assignment policies in Local Security Policy configuration
        if ($UpdateSecPolRequired -eq $true) {
            Update-LocalSecurityPolicy -NewSeServiceLogonRight $NewSeServiceLogonRight
			Write-Output "Updated Local Security Policy"
        }

        Remove-Item $secEditConfigurationExport

        Write-Output "Verified Local Security Policy for $Username"
    }
}

#endregion Public Functions
