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