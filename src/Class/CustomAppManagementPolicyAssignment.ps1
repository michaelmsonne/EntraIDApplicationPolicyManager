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
function Remove-AppManagementPolicyAssignment
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
function New-AppManagementPolicyAssignment
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
