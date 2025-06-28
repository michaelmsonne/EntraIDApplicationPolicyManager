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


<#
.SYNOPSIS
Removes an existing app management policy assignment from an application.

.DESCRIPTION
This function removes a specified app management policy assignment from an application.

.PARAMETER ObjectId
The Óbject ID of the application from which the policy will be removed.

.PARAMETER PolicyId
The ID of the policy to remove from the application.

.EXAMPLE
Remove-AppManagementPolicyAssignment -ObjectId '12345' -PolicyId '67890'
#>
function Remove-CustomAppManagementPolicyAssignmentFromApp
{
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]$ObjectId,
		[Parameter(Mandatory = $true)]
		[string]$PolicyId
	)
	
	Write-Log -Level INFO -Message "Initiating removal of policy ($PolicyId) from application ($ObjectId)."
	
	try
	{
		Remove-MgApplicationAppManagementPolicyAppManagementPolicyByRef -ApplicationId $ObjectId -AppManagementPolicyId $PolicyId -ErrorAction Stop
		Write-Log -Level INFO -Message "Policy '$PolicyId' successfully removed from application '$ObjectId' successfully."
		Show-MsgBox -Prompt "Policy '$PolicyId' successfully removed from application '$ObjectId'." -Title "Remove Policy" -Icon Information -BoxType OKOnly
	}
	catch
	{
		$errorMessage = $_.Exception.Message
		Write-Log -Level ERROR -Message "Error removing the policy '$PolicyId' from the application '$ObjectId': $errorMessage"
		Show-MsgBox -Prompt "Error removing the policy from the application. Details: $errorMessage" -Title "Remove Policy Error" -Icon Critical -BoxType OKOnly
	}
}

<#
.SYNOPSIS
Assigns a new app management policy to an application.

.DESCRIPTION
This function assigns a specified app management policy to an application.

.PARAMETER ObjectId
The ID of the application to which the policy will be assigned.

.PARAMETER Policy
The policy object to assign to the application.

.EXAMPLE
New-AppManagementPolicyAssignment -Policy $policy -ObjectId '12345'
#>
function New-CustomAppManagementPolicyAssignmentFromApp
{
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[string]$ObjectId,
		[Parameter(Mandatory)]
		[string]$PolicyId
	)
	
	Write-Log -Level INFO -Message "Assigning Policy '$PolicyId' to Application '$ObjectId'."
	
	try
	{
		$body = @{
			"@odata.id" = "https://graph.microsoft.com/v1.0/policies/appManagementPolicies/$PolicyId"
		}
		New-MgApplicationAppManagementPolicyByRef -ApplicationId $ObjectId -BodyParameter $body -ErrorAction Stop
		Write-Log -Level INFO -Message "Policy '$PolicyId' assigned to application '$ObjectId' successfully."
		
		Show-MsgBox -Prompt "Policy '$policyId' assigned successfully to application '$objectId'." -Title "Assign Policy" -Icon Information -BoxType OKOnly
	}
	catch
	{
		$errorMessage = $_.Exception.Message
		if ($errorMessage -match "appManagementPolicies" -and $errorMessage -match "(already exist|uniqueness violation)")
		{
			Write-Log -Level INFO -Message "Policy '$PolicyId' is already assigned to application '$ObjectId'. Duplicate assignments are not permitted."
		}
		else
		{
			Write-Log -Level ERROR -Message "Failed to assign policy: $errorMessage"
		}
	}
}
