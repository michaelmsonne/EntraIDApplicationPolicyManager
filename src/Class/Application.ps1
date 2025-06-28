function Get-CurrentAppSecrets
{
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[string]$AppRegistrationID,
		[Parameter(Mandatory)]
		[string]$AppRegistrationName
	)
	
	$result = ""
	try
	{
		Write-Log -Level INFO -Message "Getting secrets and certificates for App Registration with Id: '$AppRegistrationID' and Name: '$AppRegistrationName'"
		
		# Retrieve the application - PasswordCredentials and KeyCredentials properties hold the secrets and certs
		$app = Get-MgApplication -ApplicationId $AppRegistrationID -ErrorAction Stop
		
		# Process password secrets
		$secrets = $app.PasswordCredentials
		if ($secrets -and $secrets.Count -gt 0)
		{
			$result += "Current secrets for App Registration '$AppRegistrationName' (ID: '$AppRegistrationID'):`r`n"
			foreach ($secret in $secrets)
			{
				$secretInfo = @"
SecretKeyId:   $($secret.KeyId)
DisplayName:   $($secret.DisplayName)
StartDate:     $($secret.StartDateTime)
EndDate:       $($secret.EndDateTime)
"@
				$result += $secretInfo + "`r`n"
			}
			Write-Log -Level INFO -Message "Retrieved secrets for App Registration '$AppRegistrationName' successfully."
		}
		else
		{
			$result += "No secrets found for App Registration '$AppRegistrationName' (ID: '$AppRegistrationID').`r`n"
			Write-Log -Level INFO -Message "No secrets found for App Registration '$AppRegistrationName'."
		}
		
		# Process certificates (KeyCredentials)
		$certs = $app.KeyCredentials
		if ($certs -and $certs.Count -gt 0)
		{
			$result += "`r`nCurrent certificates for App Registration '$AppRegistrationName' (ID: '$AppRegistrationID'):`r`n"
			foreach ($cert in $certs)
			{
				$certDisplayName = if ($cert.PSObject.Properties['DisplayName']) { $cert.DisplayName }
				else { "<n/a>" }
				$certInfo = @"
CertificateKeyId:   $($cert.KeyId)
DisplayName:        $certDisplayName
Type:               $($cert.Type)
Usage:              $($cert.Usage)
StartDate:          $($cert.StartDateTime)
EndDate:            $($cert.EndDateTime)
"@
				$result += $certInfo + "`r`n`r`n"
			}
			Write-Log -Level INFO -Message "Retrieved certificates for App Registration '$AppRegistrationName' successfully."
		}
		else
		{
			$result += "`r`nNo certificates found for App Registration '$AppRegistrationName' (ID: '$AppRegistrationID').`r`n"
			Write-Log -Level INFO -Message "No certificates found for App Registration '$AppRegistrationName'."
		}
	}
	catch
	{
		$result += "Error retrieving secrets and certificates for App Registration '$AppRegistrationName' (ID: '$AppRegistrationID'): $($_.Exception.Message)`r`n"
		Write-Log -Level ERROR -Message "Error retrieving secrets and certificates for App Registration '$AppRegistrationName' (ID: '$AppRegistrationID'): $($_.Exception.Message)"
	}
	return $result
}

function Get-ApplicationsCount
{
	# Get data to global data to keep
	$global:ApplicationIdentities = Get-MgApplication -All
	
	# Return data
	return $global:ApplicationIdentities.Count
}

function Get-ApplicationsFromEntraID
{
	# Clear current data in the CheckedListBox to not keep old items
	$checkedlistboxListOfApplications.Items.Clear()
	
	# If connected
	if ($global:ConnectedState)
	{
		# Log
		Write-Log -Level INFO -Message "Loading list of Applications from tenant..."
		
		# Get all managed identities
		$global:ApplicationIdentities = Get-MgApplication -All
		
		# Log
		Write-Log -Level INFO -Message "Loaded and updated the list of discovered applications from the tenant."
		
		# Create a custom object with DisplayName and Id, then sort by DisplayName
		$sortedIdentities = $ApplicationIdentities | Sort-Object DisplayName | ForEach-Object {
			[PSCustomObject]@{
				DisplayName = $_.DisplayName
				Id		    = $_.Id
			}
		}
		
		# Populate the CheckedListBox with sorted managed identities
		foreach ($identity in $sortedIdentities)
		{
			$checkedlistboxListOfApplications.Items.Add($identity.DisplayName)
		}
		
		# Store the sorted identities in a global variable for later use
		$global:sortedApplicationIdentities = $sortedIdentities
		$global:filteredApplicationIdentities = $sortedIdentities
		
		# Log
		Write-Log -Level INFO -Message "List of applications updated with a total of '$(Get-ApplicationsCount)' applications"
		
		Update-NumberOfManagedIdentityCountLabel
	}
	# Else if not connected
	else
	{
		# Log
		Write-Log -Level INFO -Message "Not connected - can´t load list of applications"
	}
}