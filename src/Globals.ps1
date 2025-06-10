<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	05-06-2025 10:12
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud - blog.sonnes.cloud
	 Filename:     	Globals.ps1
	===========================================================================
	.DESCRIPTION
		Description of the PowerShell class.
#>

#--------------------------------------------
# Declare Global Variables and Functions here
#--------------------------------------------

$global:ConnectedState = $false # Default value
$global:ApplicationIdentities
$global:clearExistingPermissions
$global:darkModeStateUI
$global:sortedApplicationIdentities
$global:filteredApplicationIdentities

$global:FormVersion = "1.0.0.0"
$global:Author = "Michael Morten Sonne"
$global:ToolName = "Entra ID Application Policy Manager"
$global:AuthorEmail = ""
$global:AuthorCompany = "Sonne´s Cloud"

$global:GitHubProfileURL = "https://github.com/michaelmsonne/"
$global:BlogURL = "https://blog.sonnes.cloud"
$global:LinkedInURL = "https://www.linkedin.com/in/michaelmsonne/"
$global:BuyMeACoffieURL = "https://buymeacoffee.com/sonnes"
$global:GitHubRepoURL = "https://github.com/michaelmsonne/EntraIDApplicationPolicyManager"

#Get username and domain for account running this tool
$global:UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

#Logfile path
$LogPath = "$Env:USERPROFILE\AppData\Local\$global:ToolName"

# Variable that provides the location of the script
[string]$ScriptDirectory = Get-ScriptDirectory

function StartAsAdmin
{
	# Check if the current process is running with elevated privileges
	$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
	
	if (-not $isElevated)
	{
		# Restart the current process as administrator
		$processPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
		#$arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$processPath`""
		
		Write-Log -Level INFO -Message "Restarting '$processPath' as administrator..."
		Start-Process $processPath -Verb RunAs
		
		# Exit the current process
		[System.Environment]::Exit(0)
	}
}

function Test-Administrator
{
	# Get the current Windows identity
	$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
	
	# Create a Windows principal object
	$principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
	
	# Check if the current principal is in the Administrator role
	return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-CurrentExecutionFilename
{
	# Get the current execution location
	$currentLocation = Get-Location
	
	# Get the path of the currently executing assembly
	# Get the path of the currently running process
	$processPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
	$scriptName = [System.IO.Path]::GetFileName($processPath)
	
	# Get the current hostname using the .NET method
	$hostname = [System.Net.Dns]::GetHostName()
	
	# Output the current location and script name
	Write-Log -Level INFO -Message "Current execution location: '$($currentLocation.Path)\$scriptName' on host '$hostname'"
}

# Checks the current execution policy for the process
function Test-ExecutionPolicy
{
	#StartAsAdmin
	
	if (Test-Administrator)
	{
		# TODO
	}
	
	try
	{
		Write-Log -Level INFO -Message "Getting PowerShell execution policy..."
		$executionPolicies = Get-ExecutionPolicy -List
		
		# Concatenate execution policies into a single string
		$policyString = ($executionPolicies | ForEach-Object { "$($_.Scope): $($_.ExecutionPolicy)" }) -join ", "
		Write-Log -Level INFO -Message "Execution policies: '$policyString'"
		
		$processPolicy = $executionPolicies | Where-Object { $_.Scope -eq 'Process' }
		$currentUserPolicy = $executionPolicies | Where-Object { $_.Scope -eq 'CurrentUser' }
		$effectivePolicy = $executionPolicies | Where-Object { $_.Scope -eq 'MachinePolicy' -or $_.Scope -eq 'UserPolicy' }
		
		if ($effectivePolicy.ExecutionPolicy -ne 'Undefined')
		{
			Write-Log -Level INFO -Message "Execution policy is set by Group Policy. Current effective policy is '$($effectivePolicy.ExecutionPolicy)'."
			return
		}
		
		if ($processPolicy.ExecutionPolicy -ne "Unrestricted" -and $processPolicy.ExecutionPolicy -ne "Bypass")
		{
			Write-Log -Level INFO -Message "Current process execution policy is '$($processPolicy.ExecutionPolicy)'."
			
			try
			{
				Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
				Write-Log -Level INFO -Message "Execution policy set to 'Bypass' for the current process."
			}
			catch
			{
				if ($_.Exception.Message -match "Security error")
				{
					Write-Log -Level WARN -Message "Security error encountered. Attempting to set execution policy to 'RemoteSigned'..."
					try
					{
						Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
						Write-Log -Level INFO -Message "Execution policy set to 'RemoteSigned' for the current process."
					}
					catch
					{
						Write-Log -Level ERROR -Message "Failed to set execution policy to 'RemoteSigned': $($_.Exception.Message)"
						
						StartAsAdmin
					}
				}
				else
				{
					Write-Log -Level ERROR -Message "Failed to set execution policy: $($_.Exception.Message)"
				}
			}
		}
		else
		{
			Write-Log -Level INFO -Message "Current process execution policy is '$($processPolicy.ExecutionPolicy)'. No need to change."
		}
	}
	catch
	{
		Write-Log -Level ERROR -Message "An error occurred: $($_.Exception.Message)"
	}
}

# Get current Windows colour theme (dard or light)
function Test-WindowsInDarkMode
{
	# Path to the registry key
	$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
	$registryValueName = "AppsUseLightTheme"
	
	try
	{
		# Get the value of the registry key
		$useLightTheme = Get-ItemProperty -Path $registryPath -Name $registryValueName -ErrorAction Stop
		
		# Determine the theme mode based on the registry value
		if ($useLightTheme.$registryValueName -eq 0)
		{
			return $true # Dark mode
			
			Write-Log -Level INFO -Message "Detected Windows is running as Dark mode - setting application to this theme as default"
		}
		else
		{
			return $false # Light mode
			
			Write-Log -Level INFO -Message "Detected Windows is running as Light mode - setting application to this theme as default"
		}
	}
	catch
	{
		#Write-Error "Failed to determine Windows theme mode: $_"
		return $false
	}
}

#CheckLogPath function
Function CheckLogPath
{
<#
	.SYNOPSIS
		CheckLogPath returns the value if logfile path exits or not.

	.OUTPUTS
		System.String
	
	.NOTES
		Returns the correct path within a packaged executable.
#>
	try
	{
		$FolderName = $LogPath
		if (Test-Path $FolderName)
		{
			#Write to logfile if exists
			Write-Log -Level INFO -Message "The application log path exists: '$LogPath'"
		}
		else
		{
			#Create logfile of not exists
			New-Item $FolderName -ItemType Directory
			
			# Log
			Write-Log -Level INFO -Message "The application log path does not exists and is created: '$LogPath'"
		}
	}
	# Catch specific types of exceptions thrown by one of those commands
	catch [System.Exception]
	{
		# Log
		Write-Log -Level ERROR -Message $($Error[0].Exception.Message)
	}
	# Catch all other exceptions thrown by one of those commands
	catch
	{
		# Log
		Write-Log -Level ERROR -Message $($Error[0].Exception.Message)
	}
}

#Logfile write log function
Function Write-Log
{
<#
	.SYNOPSIS
		Save the information to specified logfile
	
	.DESCRIPTION
		A detailed description of the Write-Log function.
	
	.PARAMETER Level
		Set the information level in the logfile.
	
	.PARAMETER Message
		The message to be logged in the logfile
	
	.PARAMETER logfile
		The selected logfile to write to (there is a default logfile)
	
	.EXAMPLE
		PS C:\> Write-Log -Level INFO -Message 'value1'
	
	.NOTES
		Additional information about the function.
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $False)]
		[ValidateSet("INFO", "WARN", "ERROR", "FATAL", "DEBUG")]
		[String]$Level = "INFO",
		[Parameter(Mandatory = $True)]
		[string]$Message,
		[Parameter(Mandatory = $False)]
		[string]$logfile = "$LogPath\$($ToolName)_Log_$($env:computername)" + "_" + (Get-Date -Format "dd-MM-yyyy") + ".log"
	)
	
	$Stamp = (Get-Date).toString("dd/MM/yyyy HH:mm:ss")
	$Line = "$Stamp : $Level : $UserName : $Message"
	If ($logfile)
	{
		Add-Content $logfile -Value $Line
	}
	
	# Update the log TextBox in the UI
	Update-Log -message $Message
	
	#HOW TO ADD A LOG ENTRY: Write-Log -Level INFO -Message "The application is started"
}

# Function to update the log textbox (UI)
function Update-Log
{
	param (
		[string]$message
	)
	#$textboxLog.Value.Text += "$message" + "´n"
	
	# Append the new log entry to the TextBox
	$timestamp = Get-Date -Format "dd-MM-yyyy HH:mm:ss"
	$textboxLog.AppendText("[$timestamp] $message`r`n")
	
	# Ensure the TextBox scrolls to the latest entry
	$textboxLog.SelectionStart = $textboxLog.Text.Length
	$textboxLog.ScrollToCaret()
}

function Show-InputBox
{
	param
	(
		[string]$message = $(Throw "You must enter a prompt message"),
		[string]$title = "Input",
		[string]$default
	)
	
	[reflection.assembly]::loadwithpartialname("microsoft.visualbasic") | Out-Null
	[microsoft.visualbasic.interaction]::InputBox($message, $title, $default)
}

function Show-MsgBox
{
	[CmdletBinding()]
	param (
		# Define the message to be displayed in the message box.
		[Parameter(Position = 0, Mandatory = $true)]
		[string]$Prompt,
		# Define the title for the message box (optional).
		[Parameter(Position = 1, Mandatory = $false)]
		[string]$Title = "",
		# Define the icon type for the message box (optional).
		[Parameter(Position = 2, Mandatory = $false)]
		[ValidateSet("Information", "Question", "Critical", "Exclamation")]
		[string]$Icon = "Information",
		# Define the type of buttons in the message box (optional).
		[Parameter(Position = 3, Mandatory = $false)]
		[ValidateSet("OKOnly", "OKCancel", "AbortRetryIgnore", "YesNoCancel", "YesNo", "RetryCancel")]
		[string]$BoxType = "OkOnly",
		# Define the default button for the message box (optional).
		[Parameter(Position = 4, Mandatory = $false)]
		[ValidateSet(1, 2, 3)]
		[int]$DefaultButton = 1
	)
	
	# Load the Microsoft.VisualBasic assembly for MessageBox handling.
	[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.VisualBasic") | Out-Null
	
	# Map the provided $Icon to the corresponding VB.NET enum value.
	switch ($Icon)
	{
		"Question" { $vb_icon = [microsoft.visualbasic.msgboxstyle]::Question }
		"Critical" { $vb_icon = [microsoft.visualbasic.msgboxstyle]::Critical }
		"Exclamation" { $vb_icon = [microsoft.visualbasic.msgboxstyle]::Exclamation }
		"Information" { $vb_icon = [microsoft.visualbasic.msgboxstyle]::Information }
	}
	# Map the provided $BoxType to the corresponding VB.NET enum value.
	switch ($BoxType)
	{
		"OKOnly" { $vb_box = [microsoft.visualbasic.msgboxstyle]::OKOnly }
		"OKCancel" { $vb_box = [microsoft.visualbasic.msgboxstyle]::OkCancel }
		"AbortRetryIgnore" { $vb_box = [microsoft.visualbasic.msgboxstyle]::AbortRetryIgnore }
		"YesNoCancel" { $vb_box = [microsoft.visualbasic.msgboxstyle]::YesNoCancel }
		"YesNo" { $vb_box = [microsoft.visualbasic.msgboxstyle]::YesNo }
		"RetryCancel" { $vb_box = [microsoft.visualbasic.msgboxstyle]::RetryCancel }
	}
	# Map the provided $DefaultButton to the corresponding VB.NET enum value.
	switch ($Defaultbutton)
	{
		1 { $vb_defaultbutton = [microsoft.visualbasic.msgboxstyle]::DefaultButton1 }
		2 { $vb_defaultbutton = [microsoft.visualbasic.msgboxstyle]::DefaultButton2 }
		3 { $vb_defaultbutton = [microsoft.visualbasic.msgboxstyle]::DefaultButton3 }
	}
	
	# Combine the icon, button type, and default button values to determine the message box style.
	$popuptype = $vb_icon -bor $vb_box -bor $vb_defaultbutton
	
	# Show the message box with the provided parameters and capture the user's response.
	$ans = [Microsoft.VisualBasic.Interaction]::MsgBox($prompt, $popuptype, $title)
	
	# Return the user's response.
	return $ans
}

#Sample function that provides the location of the script
function Get-ScriptDirectory
{
<#
	.SYNOPSIS
		Get-ScriptDirectory returns the proper location of the script.

	.OUTPUTS
		System.String
	
	.NOTES
		Returns the correct path within a packaged executable.
#>
	[OutputType([string])]
	param ()
	if ($null -ne $hostinvocation)
	{
		Split-Path $hostinvocation.MyCommand.path
	}
	else
	{
		Split-Path $script:MyInvocation.MyCommand.Path
	}
}

function Get-ApplicationsCount
{
	# Get data to global data to keep
	$global:ApplicationIdentities = Get-MgApplication -All
	
	# Return data
	return $global:ApplicationIdentities.Count
}

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

# Function to connect to Microsoft Graph
function ConnectToGraph
{
	param (
		[string]$TenantId
	)
	
	# Log
	Write-Log -Level INFO -Message "Starting to connect to Microsoft Graph..."
	
	# Connect with or without tenant ID
	if ($TenantId)
	{
		Write-Log -Level INFO -Message "Connecting to Microsoft Graph with Tenant ID: $TenantId"
		Connect-MgGraph -TenantId $TenantId -NoWelcome -Scopes 'Application.Read.All', 'AppRoleAssignment.ReadWrite.All', 'Policy.ReadWrite.ApplicationConfiguration'
	}
	else
	{
		Write-Log -Level INFO -Message "Connecting to Microsoft Graph without specific Tenant ID"
		Connect-MgGraph -NoWelcome -Scopes 'Application.Read.All', 'AppRoleAssignment.ReadWrite.All', 'Policy.ReadWrite.ApplicationConfiguration'
	}
	
	# Check if the connection is successful
	try
	{
		# Get currect context (if any)
		$context = Get-MgContext -ErrorAction SilentlyContinue
		
		# If context exists
		if ($context -and $context.ClientId -and $context.TenantId)
		{
			# Log
			Write-Log -Level INFO -Message "Connected to Microsoft Graph as '$($context.Account)' (Tenant: '$($context.TenantId)', App: '$($context.AppName)', Auth: $($context.AuthType)/$($context.ContextScope), Token: '$($context.TokenCredentialType)')"
			
			# Set state
			$global:ConnectedState = $true
		}
		else
		{
			# Log
			Write-Log -Level ERROR -Message "Failed to connect to Microsoft Graph. Context is incomplete. Error: $_"
			
			# Set state
			$global:ConnectedState = $false
		}
	}
	catch
	{
		# Log
		Write-Log -Level ERROR -Message "Failed to connect to Microsoft Graph. Error: $_"
		
		# Set state
		$global:ConnectedState = $false
	}
}

function Get-LatestReleaseFromGitHub
{
	$repo = "michaelmsonne/ApplicationManagementPolicyManager"
	$file = "ApplicationManagementPolicyManager.exe"
	$releasesUrl = "https://api.github.com/repos/$repo/releases"
	
	Write-Log -Level INFO -Message "Determining latest release..."
	$tag = (Invoke-WebRequest -Uri $releasesUrl -UseBasicParsing | ConvertFrom-Json)[0].tag_name
	
	$downloadUrl = "https://github.com/$repo/releases/download/$tag/$file"
	Write-Log -Level INFO -Message "Downloading latest release from GitHub API at: '$downloadUrl'"
	
	# Get the current execution location
	$currentLocation = Get-Location
	
	# Get the path
	$outputFile = Join-Path -Path $env:USERPROFILE\Downloads -ChildPath $file #$($currentLocation.Path)
	Invoke-WebRequest -Uri $downloadUrl -OutFile $outputFile
	
	# Ask user
	$ConfirmStartLAstDownloadedVFromGitHub = Show-MsgBox -Prompt "Latest release v. $tag on GitHub is downloaded successfully to the path:`r`n`r`n'$outputFile'.`r`n`r`nDo you want to restart the application with the new version?" -Title "Download Complete" -Icon Question -BoxType YesNo -DefaultButton 1
	
	# If user comfirmed
	If ($ConfirmStartLAstDownloadedVFromGitHub -eq "Yes")
	{
		# Log
		Write-Log -Level INFO -Message "Restarting application with the new version $tag ... - confirmed by user"
		
		# Start
		Start-Process -FilePath $outputFile
		$formManagedIdentityPermi.Close()
		Stop-Process -Id $PID
	}
	else
	{
		# Log
		Write-Log -Level INFO -Message "The new version $tag is downloaded to: $outputFile'"
		
		Show-MsgBox -Title "Download location" -Prompt "The new version '$tag' is downloaded to:`r`n`r`n'$outputFile'`r`n`r`nHere you can start it later when needed :)" -Icon Information -BoxType OKOnly
	}
}

function Get-TenantId
{
	param (
		[string]$LookupInputData
	)
	
	# Log the received parameters
	Write-Log -Level INFO -Message "Trying to get tenant data for: '$LookupInputData'"
	
	# Check if the input is a domain name or tenant ID
	if ($LookupInputData -match '^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$')
	{
		Write-Log -Level INFO -Message "Input '$LookupInputData' is a domain"
		
		# Input is a domain name
		$url = "https://login.microsoftonline.com/$LookupInputData/.well-known/openid-configuration"
	}
	else
	{
		Write-Log -Level INFO -Message "Input '$LookupInputData' is a tenant ID"
		
		# Input is a tenant ID
		$url = "https://login.microsoftonline.com/$LookupInputData/v2.0/.well-known/openid-configuration"
	}
	
	Write-Log -Level INFO -Message "Sending GET request for '$LookupInputData' - URL: '$url'"
	
	try
	{
		# Send GET request to get data needed
		$response = Invoke-RestMethod -Uri $url -Method Get
		
		# Log (debug data only)
		#Write-Log -Level INFO -Message "Response: $($response | Out-String)"
		
		# Extract the tenant ID from the issuer field
		$tenantId = $response.issuer -replace 'https://sts.windows.net/', '' -replace 'https://login.microsoftonline.com/', '' -replace '/v2.0', '' -replace '/', ''
		
		# Log
		Write-Log -Level INFO -Message "Extracted Tenant ID: '$tenantId' from GET response"
		
		# Return data
		return $tenantId
	}
	catch [System.Net.WebException] {
		# Log specific web exception
		Write-Log -Level ERROR -Message "WebException occurred: $($_.Exception.Message)"
		Write-Log -Level ERROR -Message "Status: $($_.Exception.Status)"
		if ($_.Exception.Response)
		{
			$responseStream = $_.Exception.Response.GetResponseStream()
			$reader = New-Object System.IO.StreamReader($responseStream)
			$responseBody = $reader.ReadToEnd()
			Write-Log -Level ERROR -Message "Response Body: $responseBody"
		}
		return $null
	}
	catch [System.Exception] {
		# Log general exception
		Write-Log -Level ERROR -Message "Failed to retrieve tenant ID for input: $LookupInputData. Error: $($_.Exception.Message)"
		return $null
	}
}

function Get-PolicyList
{
	[CmdletBinding()]
	param ()
	
	try
	{
		Write-Log -Level INFO -Message "Retrieving app management policies from Entra ID..."
		$policyList = Get-MgPolicyAppManagementPolicy -All -ErrorAction Stop
		Write-Log -Level INFO -Message "Retrieved a total of $($policyList.Count) app management policies."
		return $policyList
	}
	catch
	{
		Write-Log -Level ERROR -Message "Error retrieving app management policies: $($_.Exception.Message)"
		return @()
	}
}

function Assign-CustomAppManagementPolicyToApp
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

function Remove-CustomAppManagementPolicyAssignmentFromApp
{
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]$ObjectId,
		[Parameter(Mandatory = $true)]
		[string]$PolicyId
	)
	
	Write-Log -Level INFO -Message "Removing Policy '$PolicyId' from Application '$ObjectId'."
	try
	{
		Remove-MgApplicationAppManagementPolicyAppManagementPolicyByRef -ApplicationId $ObjectId -AppManagementPolicyId $PolicyId -ErrorAction Stop
		Write-Log -Level INFO -Message "Policy '$PolicyId' removed from application '$ObjectId' successfully."
		Show-MsgBox -Prompt "Policy '$PolicyId' removed successfully from application '$ObjectId'." -Title "Remove Policy" -Icon Information -BoxType OKOnly
	}
	catch
	{
		$errorMessage = $_.Exception.Message
		Write-Log -Level ERROR -Message "Failed to remove policy '$PolicyId' from application '$ObjectId': $errorMessage"
		Show-MsgBox -Prompt "Failed to remove policy. Error: $errorMessage" -Title "Remove Policy Error" -Icon Critical -BoxType OKOnly
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

function Get-CurrentAppSecrets {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$AppRegistrationID,
        [Parameter(Mandatory)]
        [string]$AppRegistrationName
    )
    
    $result = ""
    try {
        Write-Log -Level INFO -Message "Getting secrets and certificates for App Registration with Id: '$AppRegistrationID' and Name: '$AppRegistrationName'"
        
        # Retrieve the application – PasswordCredentials and KeyCredentials properties hold the secrets and certs
        $app = Get-MgApplication -ApplicationId $AppRegistrationID -ErrorAction Stop
        
        # Process password secrets
        $secrets = $app.PasswordCredentials
        if ($secrets -and $secrets.Count -gt 0) {
            $result += "Current secrets for App Registration '$AppRegistrationName' (ID: '$AppRegistrationID'):`r`n"
            foreach ($secret in $secrets) {
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
        else {
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

function Get-AppAssignedPolicies
{
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]$AppId
	)
	
	try
	{
		Write-Log -Level INFO -Message "Getting assigned App Protection Policy for Application with Id: '$AppId'"
		
		# Retrieve the application with its assigned policies expanded
		$app = Get-MgApplication -ApplicationId $AppId -ExpandProperty appManagementPolicies -ErrorAction Stop
		
		if ($app.appManagementPolicies)
		{
			$policyList = $app.appManagementPolicies | ForEach-Object {
				# Format the JSON with depth 10
				$jsonRestrictions = $_.Restrictions | ConvertTo-Json -Depth 10
				$details = "Name: $($_.DisplayName)`r`n" +
				"ID: $($_.Id)`r`n" +
				"Description: $($_.Description)`r`n" +
				"Enabled: $($_.IsEnabled)`r`n" +
				"Restrictions: `r`n$jsonRestrictions`r`n" +
				"----------------------"
				$details
			}
			
			Write-Log -Level INFO -Message "Received assigned App Protection Policy for Application with Id: '$AppId'"
			
			return $policyList -join "`r`n"
		}
		else
		{
			Write-Log -Level INFO -Message "No App Protection policies are assigned to Application ID '$AppId'."
			
			return "No App Protection policies are assigned to Application ID '$AppId'."
		}
	}
	catch
	{
		Write-Log -Level ERROR -Message "Error retrieving assigned App Protection policies for Application ID '$AppId' : $($_.Exception.Message)"
		
		throw "Error retrieving assigned App Protection policies for Application ID '$AppId' : $($_.Exception.Message)"
	}
}

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
