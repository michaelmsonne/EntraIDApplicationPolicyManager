# Validate the current PowerShell modules required to execute this tool
function Test-Modules
{
	# Array of modules needed with minimum versions
	$requiredModules = @(
		@{ Name = "Microsoft.Graph.Authentication"; MinVersion = "2.25.0" },
		@{ Name = "Microsoft.Graph.Identity.SignIns"; MinVersion = "2.25.0" }
	)
	
	# Log
	Write-Log -Level INFO -Message "Starting check for needed PowerShell Modules..."
	
	$modulesToInstall = @()
	foreach ($module in $requiredModules)
	{
		Write-Log -Level INFO -Message "Checking module '$($module.Name)'..."
		$installedVersions = Get-Module -ListAvailable $module.Name
		if ($installedVersions)
		{
			# Check if Beta version of the module is installed
			$isBetaModule = $installedVersions | Where-Object { $_.Name -eq $module.Name -and ($_.Path -like "*Beta*" -or $_.Name -like "*Beta*") }
			if ($isBetaModule)
			{
				Write-Log -Level ERROR -Message "Beta version of module '$($module.Name)' is installed. Exiting to avoid conflicts."
				throw "Beta version of module '$($module.Name)' detected. Please uninstall the Beta module and re-run the script."
			}
			
			# Check if installed version meets the minimum version requirement
			if ($installedVersions[0].Version -lt [version]$module.MinVersion)
			{
				Write-Log -Level INFO -Message "New version required for module '$($module.Name)'. Current installed version: $($installedVersions[0].Version), required minimum version: $($module.MinVersion)"
				$modulesToInstall += $module.Name
			}
			else
			{
				Write-Log -Level INFO -Message "Module '$($module.Name)' meets the minimum version requirement. Current version: $($installedVersions[0].Version)"
				Import-Module $module.Name -ErrorAction Stop
				Write-Log -Level INFO -Message "Importing module '$($module.Name)'..."
			}
		}
		else
		{
			Write-Log -Level INFO -Message "Module '$($module.Name)' is not installed."
			$modulesToInstall += $module.Name
		}
	}
	
	if ($modulesToInstall.Count -gt 0)
	{
		Write-Log -Level INFO -Message "Missing required PowerShell modules. Prompting for installation..."
		
		# Concatenate module names into a single string
		$modulesList = $modulesToInstall -join ", "
		
		# Aks if the user will install needed modules
		$ConfirmInstallMissingPowerShellModule = Show-MsgBox -Prompt "The following required PowerShell modules are missing:`r`n`r`n$modulesList.`r`n`r`nWould you like to install these modules now?" -Title "Missing required PowerShell modules" -Icon Question -BoxType YesNo -DefaultButton 2
		
		# Get confirmation
		If ($ConfirmInstallMissingPowerShellModule -eq "Yes")
		{
			# Log
			Write-Log -Level INFO -Message "Set to install needed PowerShell Modules - confirmed by user"
			
			Write-Log -Level INFO -Message "Installing modules..."
			foreach ($module in $modulesToInstall)
			{
				Write-Log -Level INFO -Message "Installing module '$module'..."
				Install-Module $module -Scope CurrentUser -Force -ErrorAction Stop
				Write-Log -Level INFO -Message "Importing module '$module'..."
				Import-Module $module -ErrorAction Stop
			}
			Write-Log -Level INFO -Message "Modules installed."
		}
		else
		{
			# Log
			Write-Log -Level INFO -Message "Set to keep current state for reset existing permissions - confirmation to change is cancled by user"
			
			Write-Log -Level ERROR -Message "Exiting setup. Please install required modules and re-run the setup."
		}
	}
	
	# Log
	Write-Log -Level INFO -Message "Check for needed PowerShell Modules complete"
}