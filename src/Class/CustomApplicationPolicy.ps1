function Create-DevPolicy
{
	$params = @{
		displayName  = "Development App Policy"
		description  = "Allows use of Client Secrets for Dev apps - Created on $(Get-Date -Format 'yyyy-MM-dd')"
		isEnabled    = $true
		restrictions = @{
			passwordCredentials = @(
				@{
					restrictionType = "passwordAddition"
					state		    = "disabled"
					maxLifetime	    = $null
				}
			)
		}
	}
	
	try
	{
		$newPolicy = New-MgPolicyAppManagementPolicy -BodyParameter $params -ErrorAction Stop
		
		Write-Log -Level INFO -Message "Development App Policy created successfully. Policy ID: $($newPolicy.Id)"
		Show-MsgBox -Prompt "Development App Policy created successfully." -Title "Create Dev Policy" -Icon Information -BoxType OKOnly
	}
	catch
	{
		$errorMessage = $_.Exception.Message
		
		# Log
		Write-Log -Level ERROR -Message "Failed to create Development App Policy: $errorMessage"
		
		Show-MsgBox -Prompt "Failed to create Development App Policy: $errorMessage" -Title "Error Creating Dev Policy" -Icon Critical -BoxType OKOnly
	}
}

function New-AppManagementPolicy
{
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[string]$DisplayName,
		[Parameter(Mandatory)]
		[string]$Description,
		[Parameter(Mandatory)]
		[string]$PasswordMaxLifetime,
		[Parameter(Mandatory)]
		[string]$KeyMaxLifetime,
		[Parameter(Mandatory)]
		[string]$PasswordState,
		# Expecting "enabled" or "disabled"
		[Parameter(Mandatory)]
		[string]$KeyState,
		# Expecting "enabled" or "disabled"
		[Parameter(Mandatory = $false)]
		[bool]$Enabled = $true
	)
	
	# TODO UPDATE TO SUPPORT ALL FEATURES
	
	# Convert lifetime values to ISO 8601 if necessary
	if ($PasswordMaxLifetime -match '^\d+$')
	{
		$PasswordMaxLifetime = "P$PasswordMaxLifetime" + "D"
	}
	if ($KeyMaxLifetime -match '^\d+$')
	{
		$KeyMaxLifetime = "P$KeyMaxLifetime" + "D"
	}
	
	# Build the request body including the specific state for each restriction
	$params = @{
		displayName  = $DisplayName
		description  = $Description
		isEnabled    = $Enabled
		restrictions = @{
			passwordCredentials = @(
				@{
					restrictionType					    = "passwordLifetime"
					state							    = $PasswordState
					maxLifetime						    = $PasswordMaxLifetime
					restrictForAppsCreatedAfterDateTime = [System.DateTime]::Parse("2014-10-19T10:37:00Z")
				},
				@{
					restrictionType					    = "symmetricKeyLifetime"
					state							    = $KeyState
					maxLifetime						    = $KeyMaxLifetime
					restrictForAppsCreatedAfterDateTime = [System.DateTime]::Parse("2014-10-19T10:37:00Z")
				}
			)
		}
	}
	
	try
	{
		New-MgPolicyAppManagementPolicy -BodyParameter $params -ErrorAction Stop
		Write-Log -Level INFO -Message "App management policy '$DisplayName' created successfully."
	}
	catch
	{
		Write-Log -Level ERROR -Message "Error creating app management policy: $($_.Exception.Message)"
	}
}
