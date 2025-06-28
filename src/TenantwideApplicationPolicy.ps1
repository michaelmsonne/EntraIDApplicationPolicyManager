# Function: Load the default tenant policy details
function Load-CurrentDefaultApplicationPolicy
{
	try
	{
		# Log
		Write-Log -Level INFO -Message "Loading Default app management tenant policy from Entra ID..."
		
		$policy = Get-MgPolicyDefaultAppManagementPolicy -ErrorAction Stop
		
		# Log
		Write-Log -Level INFO -Message "Loaded Default app management tenant policy from Entra ID."
		
		$txtDefaultPolicyDisplayName.Text = $policy.DisplayName
		$txtDefaultPolicyDescription.Text = $policy.Description
		$chkEnabled.Checked = $policy.isEnabled
		
		# Show the raw JSON data for the policy
		$txtDetails.Text = ($policy | ConvertTo-Json -Depth 10)
		
		<#
		$txtDefaultPolicyDisplayName.Text = $policy.DisplayName
		$txtDefaultPolicyDescription.Text = $policy.Description
		$chkEnabled.Checked = $policy.isEnabled
		
		$details = "Policy loaded successfully.`r`n" +
		"ID: $($policy.Id)`r`n" +
		"IsEnabled: $($policy.isEnabled)`r`n" +
		"Registered App Restrictions:" + "`r`n" +
		($policy.applicationRestrictions.PasswordCredentials | Format-Table | Out-String) + "`r`n" +
		"Enterprise App Restrictions:" + "`r`n" +
		($policy.ServicePrincipalRestrictions.PasswordCredentials | Format-Table | Out-String)
		
		$txtDetails.Text = $details
		#>
		
		return $policy
	}
	catch
	{
		Show-MsgBox -Prompt "Failed to retrieve default app protection policy: $($_.Exception.Message)" -Title "Get Policy Error" -Icon Critical -BoxType OKOnly
		
		$txtDetails.Text = "Error loading default policy: $($_.Exception.Message)"
		
		# Log
		Write-Log -Level ERROR -Message "Failed to retrieve default app protection policy: $($_.Exception.Message)"
		
		return $null
	}
}

function Reset-DefaultTenantPolicy
{
	try
	{
		$confirmation = Show-MsgBox -Prompt "Are you sure you want to reset the Default Tenant Policy to Microsoft defaults? This will remove all restrictions and enable the policy." `
									-Title "Reset Policy to Default" -Icon Question -BoxType YesNo -DefaultButton 2
		if ($confirmation -ne "Yes") { return }
		
		$defaultParams = @{
			displayName			    = "Default app management tenant policy"
			description			    = "Default tenant policy that enforces app management restrictions on applications and service principals. To apply policy to targeted resources, create a new policy under appManagementPolicies collection."
			isEnabled			    = $true
			applicationRestrictions = @{
				passwordCredentials = @()
				keyCredentials	    = @()
			}
			servicePrincipalRestrictions = @{
				passwordCredentials = @()
				keyCredentials	    = @()
			}
		}
		
		Update-MgPolicyDefaultAppManagementPolicy -BodyParameter $defaultParams -ErrorAction Stop
		
		Write-Log -Level INFO -Message "Default tenant policy has been reset to Microsoft defaults."
		
		Show-MsgBox -Prompt "Default tenant policy has been reset to Microsoft defaults." -Title "Policy Reset" -Icon Information -BoxType OKOnly
		
		# Optionally refresh the UI
		$defaultPolicy = Load-CurrentDefaultApplicationPolicy
		Set-DefaultPolicyInputsFromConfig -policy $defaultPolicy
	}
	catch
	{
		Show-MsgBox -Prompt "Error resetting policy: $($_.Exception.Message)" -Title "Policy Reset Error" -Icon Exclamation -BoxType OKOnly
		Write-Log -Level ERROR -Message "Error resetting policy: $($_.Exception.Message)"
	}
}

function Get-TenantWidePolicyUpdateParams
{
	try
	{
		# Collect main policy properties from UI
		$displayName = $txtDefaultPolicyDisplayName.Text.Trim()
		$description = $txtDefaultPolicyDescription.Text.Trim()
		$isEnabled = $chkEnabled.Checked
		
		# Password Credentials Restrictions
		$passwordCredentials = @()
		
		# passwordLifetime
		$pwdLifetimeInput = $txtPwdLifetime.Text
		if ($null -eq $pwdLifetimeInput) { $pwdLifetimeInput = "" }
		if ($pwdLifetimeInput -is [array]) { $pwdLifetimeInput = $pwdLifetimeInput -join '' }
		$pwdLifetimeInput = $pwdLifetimeInput.ToString().Trim()
		if ($pwdLifetimeInput -match '^\d+$')
		{
			$pwdLifetime = "P$pwdLifetimeInput" + "D"
		}
		else
		{
			$pwdLifetime = $pwdLifetimeInput
		}
		if ($pwdLifetimeInput -and -not $pwdLifetime)
		{
			Show-MsgBox -Prompt "Invalid password lifetime. Use a number (days) or ISO 8601 duration (e.g. P90D)." -Title "Input Error" -Icon Exclamation -BoxType OKOnly
			return $null
		}
		if ($pwdLifetime)
		{
			$passwordCredentials += @{
				restrictionType					    = "passwordLifetime"
				maxLifetime						    = $pwdLifetime
				restrictForAppsCreatedAfterDateTime = [System.DateTime]::Parse($dtpPwdDate.Value.ToString("yyyy-MM-ddTHH:mm:ssZ"))
				state							    = if ($chkPwdLifetimeEnabled.Checked) { "enabled" } else { "disabled" }
			}
		}
		
		# customPasswordLifetime
		if ($chkCustomPasswordLifetimeEnabledAddToPolicy.Checked)
		{
			$passwordCredentials += @{
				restrictionType					    = "customPasswordAddition"
				maxLifetime						    = $null
				restrictForAppsCreatedAfterDateTime = [System.DateTime]::Parse($dtpCustomPasswordDate.Value.ToString("yyyy-MM-ddTHH:mm:ssZ"))
				state							    = if ($chkCustomPasswordLifetimeEnabled.Checked) { "enabled" } else { "disabled" }
			}
		}
		
		# symmetricKeyLifetime
		$symmetricKeyLifetimeInput = $txtSymmetricKeyLifetime.Text
		if ($null -eq $symmetricKeyLifetimeInput) { $symmetricKeyLifetimeInput = "" }
		if ($symmetricKeyLifetimeInput -is [array]) { $symmetricKeyLifetimeInput = $symmetricKeyLifetimeInput -join '' }
		$symmetricKeyLifetimeInput = $symmetricKeyLifetimeInput.ToString().Trim()
		if ($symmetricKeyLifetimeInput -match '^\d+$')
		{
			$symmetricKeyLifetime = "P$symmetricKeyLifetimeInput" + "D"
		}
		else
		{
			$symmetricKeyLifetime = $symmetricKeyLifetimeInput
		}
		if ($symmetricKeyLifetimeInput -and -not $symmetricKeyLifetime)
		{
			Show-MsgBox -Prompt "Invalid symmetric key lifetime. Use a number (days) or ISO 8601 duration (e.g. P90D)." -Title "Input Error" -Icon Exclamation -BoxType OKOnly
			return $null
		}
		if ($symmetricKeyLifetime)
		{
			$passwordCredentials += @{
				restrictionType					    = "symmetricKeyLifetime"
				maxLifetime						    = $symmetricKeyLifetime
				restrictForAppsCreatedAfterDateTime = [System.DateTime]::Parse($dtpSymmetricKeyDate.Value.ToString("yyyy-MM-ddTHH:mm:ssZ"))
				state							    = if ($chkSymmetricKeyLifetimeEnabled.Checked) { "enabled" } else { "disabled" }
			}
		}
		
		# passwordAddition
		$pwdAdditionLifetimeInput = $txtPwdAdditionLifetime.Text
		if ($null -eq $pwdAdditionLifetimeInput) { $pwdAdditionLifetimeInput = "" }
		if ($pwdAdditionLifetimeInput -is [array]) { $pwdAdditionLifetimeInput = $pwdAdditionLifetimeInput -join '' }
		$pwdAdditionLifetimeInput = $pwdAdditionLifetimeInput.ToString().Trim()
		if ($pwdAdditionLifetimeInput -match '^\d+$')
		{
			$pwdAdditionLifetime = "P$pwdAdditionLifetimeInput" + "D"
		}
		else
		{
			$pwdAdditionLifetime = $pwdAdditionLifetimeInput
		}
		if ($pwdAdditionLifetimeInput -and -not $pwdAdditionLifetime)
		{
			Show-MsgBox -Prompt "Invalid password addition lifetime. Use a number (days) or ISO 8601 duration (e.g. P90D)." -Title "Input Error" -Icon Exclamation -BoxType OKOnly
			return $null
		}
		if ($pwdAdditionLifetime)
		{
			$passwordCredentials += @{
				restrictionType					    = "passwordAddition"
				maxLifetime						    = $pwdAdditionLifetime
				restrictForAppsCreatedAfterDateTime = [System.DateTime]::Parse($dtpPwdDate.Value.ToString("yyyy-MM-ddTHH:mm:ssZ"))
				state							    = "enabled"
			}
		}
		
		# customPasswordAddition
		$customPwdAdditionLifetimeInput = $txtCustomPwdAdditionLifetime.Text
		if ($null -eq $customPwdAdditionLifetimeInput) { $customPwdAdditionLifetimeInput = "" }
		if ($customPwdAdditionLifetimeInput -is [array]) { $customPwdAdditionLifetimeInput = $customPwdAdditionLifetimeInput -join '' }
		$customPwdAdditionLifetimeInput = $customPwdAdditionLifetimeInput.ToString().Trim()
		if ($customPwdAdditionLifetimeInput -match '^\d+$')
		{
			$customPwdAdditionLifetime = "P$customPwdAdditionLifetimeInput" + "D"
		}
		else
		{
			$customPwdAdditionLifetime = $customPwdAdditionLifetimeInput
		}
		if ($customPwdAdditionLifetimeInput -and -not $customPwdAdditionLifetime)
		{
			Show-MsgBox -Prompt "Invalid custom password addition lifetime. Use a number (days) or ISO 8601 duration (e.g. P90D)." -Title "Input Error" -Icon Exclamation -BoxType OKOnly
			return $null
		}
		if ($customPwdAdditionLifetime)
		{
			$passwordCredentials += @{
				restrictionType					    = "customPasswordAddition"
				maxLifetime						    = $customPwdAdditionLifetime
				restrictForAppsCreatedAfterDateTime = [System.DateTime]::Parse($dtpCustomPasswordDate.Value.ToString("yyyy-MM-ddTHH:mm:ssZ"))
				state							    = if ($chkCustomPasswordLifetimeEnabled.Checked) { "enabled" } else { "disabled" }
			}
		}
		
		# symmetricKeyAddition
		$symmetricKeyAdditionLifetimeInput = $txtSymmetricKeyAdditionLifetime.Text
		if ($null -eq $symmetricKeyAdditionLifetimeInput) { $symmetricKeyAdditionLifetimeInput = "" }
		if ($symmetricKeyAdditionLifetimeInput -is [array]) { $symmetricKeyAdditionLifetimeInput = $symmetricKeyAdditionLifetimeInput -join '' }
		$symmetricKeyAdditionLifetimeInput = $symmetricKeyAdditionLifetimeInput.ToString().Trim()
		if ($symmetricKeyAdditionLifetimeInput -match '^\d+$')
		{
			$symmetricKeyAdditionLifetime = "P$symmetricKeyAdditionLifetimeInput" + "D"
		}
		else
		{
			$symmetricKeyAdditionLifetime = $symmetricKeyAdditionLifetimeInput
		}
		if ($symmetricKeyAdditionLifetimeInput -and -not $symmetricKeyAdditionLifetime)
		{
			Show-MsgBox -Prompt "Invalid symmetric key addition lifetime. Use a number (days) or ISO 8601 duration (e.g. P90D)." -Title "Input Error" -Icon Exclamation -BoxType OKOnly
			return $null
		}
		if ($symmetricKeyAdditionLifetime)
		{
			$passwordCredentials += @{
				restrictionType					    = "symmetricKeyAddition"
				maxLifetime						    = $symmetricKeyAdditionLifetime
				restrictForAppsCreatedAfterDateTime = [System.DateTime]::Parse($dtpSymmetricKeyDate.Value.ToString("yyyy-MM-ddTHH:mm:ssZ"))
				state							    = if ($chkSymmetricKeyLifetimeEnabled.Checked) { "enabled" } else { "disabled" }
			}
		}
		
		# Key Credentials Restrictions
		$keyCredentials = @()
		$keyLifetimeInput = $txtKeyLifetime.Text
		if ($null -eq $keyLifetimeInput) { $keyLifetimeInput = "" }
		if ($keyLifetimeInput -is [array]) { $keyLifetimeInput = $keyLifetimeInput -join '' }
		$keyLifetimeInput = $keyLifetimeInput.ToString().Trim()
		if ($keyLifetimeInput -match '^\d+$')
		{
			$keyLifetime = "P$keyLifetimeInput" + "D"
		}
		else
		{
			$keyLifetime = $keyLifetimeInput
		}
		if ($keyLifetimeInput -and -not $keyLifetime)
		{
			Show-MsgBox -Prompt "Invalid key lifetime. Use a number (days) or ISO 8601 duration (e.g. P180D)." -Title "Input Error" -Icon Exclamation -BoxType OKOnly
			return $null
		}
		if ($keyLifetime)
		{
			$keyCredentials += @{
				restrictionType					    = "asymmetricKeyLifetime"
				maxLifetime						    = $keyLifetime
				restrictForAppsCreatedAfterDateTime = [System.DateTime]::Parse($dtpKeyDate.Value.ToString("yyyy-MM-ddTHH:mm:ssZ"))
				state							    = if ($chkKeyLifetimeEnabled.Checked) { "enabled" } else { "disabled" }
			}
		}
		
		# Build the params hash
		$params = @{
			displayName			    = $displayName
			description			    = $description
			isEnabled			    = $isEnabled
			applicationRestrictions = @{
				passwordCredentials = $passwordCredentials
				keyCredentials	    = $keyCredentials
			}
		}
		return $params
	}
	catch
	{
		Write-Log -Level ERROR -Message "Error collecting policy update params: $($_.Exception.Message)"
		Show-MsgBox -Prompt "Error collecting policy update params: $($_.Exception.Message)" -Title "Input Error" -Icon Exclamation -BoxType OKOnly
		return $null
	}
}

function Set-DefaultPolicyInputsFromConfig
{
	param (
		$policy # The policy object returned from the tenant
	)
	
	# Helper to extract a restriction by type
	function Get-Restriction ($restrictions, $type)
	{
		if ($restrictions)
		{
			return $restrictions | Where-Object { $_.restrictionType -eq $type }
		}
		return $null
	}
	
	$appRestrictions = $policy.applicationRestrictions
	$pwdCreds = $appRestrictions.passwordCredentials
	$keyCreds = $appRestrictions.keyCredentials
	
	# --- Handle empty restrictions (reset/default policy) ---
	if ((-not $pwdCreds -or $pwdCreds.Count -eq 0) -and (-not $keyCreds -or $keyCreds.Count -eq 0))
	{
		# Password
		if ($null -ne $txtPwdLifetime) { $txtPwdLifetime.Text = "" }
		if ($null -ne $chkPwdLifetimeEnabled) { $chkPwdLifetimeEnabled.Checked = $false }
		if ($null -ne $dtpPwdDate) { $dtpPwdDate.Value = [datetime]::Now }
		
		# Symmetric Key
		if ($null -ne $txtSymmetricKeyLifetime) { $txtSymmetricKeyLifetime.Text = "" }
		if ($null -ne $chkSymmetricKeyLifetimeEnabled) { $chkSymmetricKeyLifetimeEnabled.Checked = $false }
		if ($null -ne $dtpSymmetricKeyDate) { $dtpSymmetricKeyDate.Value = [datetime]::Now }
		
		# Custom Password
		if ($null -ne $txtCustomPasswordLifetime) { $txtCustomPasswordLifetime.Text = "" }
		if ($null -ne $chkCustomPasswordLifetimeEnabled) { $chkCustomPasswordLifetimeEnabled.Checked = $false }
		if ($null -ne $chkCustomPasswordLifetimeEnabledAddToPolicy) { $chkCustomPasswordLifetimeEnabledAddToPolicy.Checked = $false }
		if ($null -ne $dtpCustomPasswordDate) { $dtpCustomPasswordDate.Value = [datetime]::Now }
		
		# Key
		if ($null -ne $txtKeyLifetime) { $txtKeyLifetime.Text = "" }
		if ($null -ne $chkKeyLifetimeEnabled) { $chkKeyLifetimeEnabled.Checked = $false }
		if ($null -ne $dtpKeyDate) { $dtpKeyDate.Value = [datetime]::Now }
		
		return
	}
	
	<# Password Lifetime
	$pwdLifetime = Get-Restriction $pwdCreds 'passwordLifetime'
	if ($pwdLifetime)
	{
		$txtPwdLifetime.Text = ($pwdLifetime.maxLifetime -replace '^P(\d+)D$', '$1')
		$dtpPwdDate.Value = [datetime]::Parse($pwdLifetime.restrictForAppsCreatedAfterDateTime)
		$chkPwdLifetimeEnabled.Checked = ($pwdLifetime.state -eq 'enabled')
	}
	else
	{
		$txtPwdLifetime.Text = ""
		$chkPwdLifetimeEnabled.Checked = $false
	}
	#>
	
	# Password Lifetime
	$pwdLifetime = Get-Restriction $pwdCreds 'passwordLifetime'
	if ($pwdLifetime)
	{
		$maxLifetime = $pwdLifetime.maxLifetime
		if ($maxLifetime -is [string])
		{
			if ($maxLifetime -match '^P(\d+)D$')
			{
				$txtPwdLifetime.Text = $matches[1] # just the number of days
			}
			elseif ($maxLifetime -match '^P\d+D$')
			{
				$txtPwdLifetime.Text = $maxLifetime # keep as ISO 8601 if not just days
			}
			else
			{
				$txtPwdLifetime.Text = "" # fallback for invalid/unsupported formats
			}
		}
		elseif ($maxLifetime -is [object] -and $maxLifetime.PSObject.Properties['Days'])
		{
			$txtPwdLifetime.Text = $maxLifetime.Days
		}
		else
		{
			$txtPwdLifetime.Text = ""
		}
		
		# Date picker assignment
		$dateValue = $pwdLifetime.restrictForAppsCreatedAfterDateTime
		if ($dateValue)
		{
			if ($dateValue -is [datetime])
			{
				$dtpPwdDate.Value = $dateValue
			}
			else
			{
				try
				{
					$dtpPwdDate.Value = [datetime]::Parse($dateValue)
				}
				catch
				{
					# fallback to today if parsing fails
					$dtpPwdDate.Value = [datetime]::Now
				}
			}
		}
		else
		{
			$dtpPwdDate.Value = [datetime]::Now
		}
		$chkPwdLifetimeEnabled.Checked = ($pwdLifetime.state -eq 'enabled')
	}
	else
	{
		$txtPwdLifetime.Text = ""
		$chkPwdLifetimeEnabled.Checked = $false
	}
	
	<# Symmetric Key Lifetime
	$symKeyLifetime = Get-Restriction $pwdCreds 'symmetricKeyLifetime'
	if ($symKeyLifetime)
	{
		$txtSymmetricKeyLifetime.Text = ($symKeyLifetime.maxLifetime -replace '^P(\d+)D$', '$1')
		$dtpSymmetricKeyDate.Value = [datetime]::Parse($symKeyLifetime.restrictForAppsCreatedAfterDateTime)
		$chkSymmetricKeyLifetimeEnabled.Checked = ($symKeyLifetime.state -eq 'enabled')
	}
	else
	{
		$txtSymmetricKeyLifetime.Text = ""
		$chkSymmetricKeyLifetimeEnabled.Checked = $false
	}
	#>
	
	# Symmetric Key Lifetime
	
	$symKeyLifetime = Get-Restriction $pwdCreds 'symmetricKeyLifetime'
	if ($symKeyLifetime)
	{
		$maxLifetime = $symKeyLifetime.maxLifetime
		if ($maxLifetime -is [string])
		{
			if ($maxLifetime -match '^P(\d+)D$')
			{
				$txtSymmetricKeyLifetime.Text = $matches[1]
			}
			elseif ($maxLifetime -match '^P\d+D$')
			{
				$txtSymmetricKeyLifetime.Text = $maxLifetime
			}
			else
			{
				$txtSymmetricKeyLifetime.Text = ""
			}
		}
		elseif ($maxLifetime -is [object] -and $maxLifetime.PSObject.Properties['Days'])
		{
			$txtSymmetricKeyLifetime.Text = $maxLifetime.Days
		}
		else
		{
			$txtSymmetricKeyLifetime.Text = ""
		}
		$dateValue = $symKeyLifetime.restrictForAppsCreatedAfterDateTime
		if ($dateValue)
		{
			if ($dateValue -is [datetime])
			{
				$dtpSymmetricKeyDate.Value = $dateValue
			}
			else
			{
				try { $dtpSymmetricKeyDate.Value = [datetime]::Parse($dateValue) }
				catch { $dtpSymmetricKeyDate.Value = [datetime]::Now }
			}
		}
		else
		{
			$dtpSymmetricKeyDate.Value = [datetime]::Now
		}
		$chkSymmetricKeyLifetimeEnabled.Checked = ($symKeyLifetime.state -eq 'enabled')
	}
	else
	{
		$txtSymmetricKeyLifetime.Text = ""
		$chkSymmetricKeyLifetimeEnabled.Checked = $false
	}
	
	
	<# Custom Password Lifetime
	$customPwdLifetime = Get-Restriction $pwdCreds 'customPasswordAddition'
	if ($customPwdLifetime)
	{
		$item = $customPwdLifetime | Select-Object -First 1
		$txtCustomPasswordLifetime.Text = ($item.maxLifetime -replace '^P(\d+)D$', '$1')
		$dtpCustomPasswordDate.Value = [datetime]::Parse($item.restrictForAppsCreatedAfterDateTime)
		$chkCustomPasswordLifetimeEnabled.Checked = ($item.state -eq 'enabled')
	}
	else
	{
		$txtCustomPasswordLifetime.Text = ""
		$chkCustomPasswordLifetimeEnabled.Checked = $false
	}
	#>
	
	# Custom Password Lifetime
	$customPwdLifetime = Get-Restriction $pwdCreds 'customPasswordAddition'
	if ($customPwdLifetime)
	{
		$item = $customPwdLifetime | Select-Object -First 1
		$maxLifetime = $item.maxLifetime
		if ($maxLifetime -is [string])
		{
			if ($maxLifetime -match '^P(\d+)D$')
			{
				#$txtCustomPasswordLifetime.Text = $matches[1]
			}
			elseif ($maxLifetime -match '^P\d+D$')
			{
				#$txtCustomPasswordLifetime.Text = $maxLifetime
			}
			else
			{
				#$txtCustomPasswordLifetime.Text = ""
			}
		}
		elseif ($maxLifetime -is [object] -and $maxLifetime.PSObject.Properties['Days'])
		{
			#$txtCustomPasswordLifetime.Text = $maxLifetime.Days
		}
		else
		{
			#$txtCustomPasswordLifetime.Text = ""
		}
		$dateValue = $item.restrictForAppsCreatedAfterDateTime
		if ($dateValue)
		{
			if ($dateValue -is [datetime])
			{
				$dtpCustomPasswordDate.Value = $dateValue
			}
			else
			{
				try { $dtpCustomPasswordDate.Value = [datetime]::Parse($dateValue) }
				catch { $dtpCustomPasswordDate.Value = [datetime]::Now }
			}
		}
		else
		{
			$dtpCustomPasswordDate.Value = [datetime]::Now
		}
		$chkCustomPasswordLifetimeEnabledAddToPolicy.Checked = $true
		$chkCustomPasswordLifetimeEnabled.Checked = ($item.state -eq 'enabled')
	}
	else
	{
		$txtCustomPasswordLifetime.Text = ""
		$chkCustomPasswordLifetimeEnabled.Checked = $false
		$chkCustomPasswordLifetimeEnabledAddToPolicy.Checked = $false
	}
	
	<# Key Lifetime (asymmetric)
	$keyLifetime = Get-Restriction $keyCreds 'asymmetricKeyLifetime'
	if ($keyLifetime)
	{
		$txtKeyLifetime.Text = ($keyLifetime.maxLifetime -replace '^P(\d+)D$', '$1')
		$dtpKeyDate.Value = [datetime]::Parse($keyLifetime.restrictForAppsCreatedAfterDateTime)
		$chkKeyLifetimeEnabled.Checked = ($keyLifetime.state -eq 'enabled')
	}
	else
	{
		$txtKeyLifetime.Text = ""
		$chkKeyLifetimeEnabled.Checked = $false
	}
	#>
	
	# Key Lifetime (asymmetric)
	$keyLifetime = Get-Restriction $keyCreds 'asymmetricKeyLifetime'
	if ($keyLifetime)
	{
		$maxLifetime = $keyLifetime.maxLifetime
		if ($maxLifetime -is [string])
		{
			if ($maxLifetime -match '^P(\d+)D$')
			{
				$txtKeyLifetime.Text = $matches[1]
			}
			elseif ($maxLifetime -match '^P\d+D$')
			{
				$txtKeyLifetime.Text = $maxLifetime
			}
			else
			{
				$txtKeyLifetime.Text = ""
			}
		}
		elseif ($maxLifetime -is [object] -and $maxLifetime.PSObject.Properties['Days'])
		{
			$txtKeyLifetime.Text = $maxLifetime.Days
		}
		else
		{
			$txtKeyLifetime.Text = ""
		}
		
		# Date picker assignment
		$dateValue = $keyLifetime.restrictForAppsCreatedAfterDateTime
		if ($dateValue)
		{
			if ($dateValue -is [datetime])
			{
				$dtpKeyDate.Value = $dateValue
			}
			else
			{
				try
				{
					$dtpKeyDate.Value = [datetime]::Parse($dateValue)
				}
				catch
				{
					$dtpKeyDate.Value = [datetime]::Now
				}
			}
		}
		else
		{
			$dtpKeyDate.Value = [datetime]::Now
		}
		$chkKeyLifetimeEnabled.Checked = ($keyLifetime.state -eq 'enabled')
	}
	else
	{
		$txtKeyLifetime.Text = ""
		$chkKeyLifetimeEnabled.Checked = $false
	}
}