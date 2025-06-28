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
$global:WebsideURL = "https://sonnes.cloud"
$global:LinkedInURL = "https://www.linkedin.com/in/michaelmsonne/"
$global:BuyMeACoffieURL = "https://buymeacoffee.com/sonnes"
$global:GitHubRepoURL = "https://github.com/michaelmsonne/EntraIDApplicationPolicyManager"

# Scopes needed for the tools features to work
$global:RequiredScopes = @('Application.Read.All', 'AppRoleAssignment.ReadWrite.All', 'Policy.ReadWrite.ApplicationConfiguration')

#Get username and domain for account running this tool
$global:UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

#Logfile path
$LogPath = "$Env:USERPROFILE\AppData\Local\$global:ToolName"

# Variable that provides the location of the script
[string]$ScriptDirectory = Get-ScriptDirectory

function Convert-TimeSpanToIsoDuration
{
	param ([string]$input)
	if ($input -match '^(\d+)\.(\d{2}):(\d{2}):(\d{2})$')
	{
		# e.g. 1.00:00:00 => P1D
		return "P$($matches[1])D"
	}
	return $input
}

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
	if ($PSCommandPath)
	{
		$exePath = $PSCommandPath
	}
	elseif ($MyInvocation.MyCommand.Path)
	{
		$exePath = $MyInvocation.MyCommand.Path
	}
	else
	{
		$exePath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
	}
	$hostname = [System.Net.Dns]::GetHostName()
	Write-Log -Level INFO -Message "Current execution location: '$exePath' on host '$hostname'"
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

<#
Sample: Write-CreationErrorAndExit -exception $exception -roles "Security Administrator, Cloud Application Administrator"
#>
function Write-CreationErrorAndExit
{
	param (
		$exception,
		$roles
	)
	if ($exception.ErrorDetails.Message.Contains("Insufficient privileges to complete the operation") -or $exception.ErrorDetails.Message.Contains("Insufficient privileges to complete the write operation"))
	{
		Write-Log "Authentication error. Please ensure you are logged in and have the correct role assignments."
		Write-Log "Minimum required roles: $roles"
		Write-Log "Error: $($exception.ToString())"
	}
	else
	{
		Write-Log "Encountered an unexpected error during script execution."
		Write-Log "Error: $($exception.ToString())"
	}
	Write-Log "Error encountered during script execution. Rerun the script with -Debug parameter for more information on failed requests."
	
	#Exit
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
		Write-Log -Level INFO -Message "Login screen opened. Please use your browser to sign in with an administrator account."
		Write-Log -Level INFO "Connecting using params: -NoWelcome -Scopes '$global:RequiredScopes' -TenantId $TenantId"
		
		Connect-MgGraph -TenantId $TenantId -NoWelcome -Scopes $global:RequiredScopes
	}
	else
	{
		Write-Log -Level INFO -Message "Connecting to Microsoft Graph without specific Tenant ID"
		Write-Log -Level INFO -Message "Login screen opened. Please use your browser to sign in with an administrator account."
		Write-Log -Level INFO "Connecting using params: -NoWelcome -Scopes '$global:RequiredScopes'"
		Connect-MgGraph -NoWelcome -Scopes $global:RequiredScopes
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

function Get-TenantId
{
	param (
		[string]$LookupInputData
	)
	
	if ([string]::IsNullOrWhiteSpace($LookupInputData))
	{
		Write-Log -Level ERROR -Message "Lookup input is empty or null."
		return $null
	}
	
	Write-Log -Level INFO -Message "Trying to get tenant data for: '$LookupInputData'"
	
	# Check if the input is a domain name or tenant ID
	if ($LookupInputData -match '^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$')
	{
		Write-Log -Level INFO -Message "Input '$LookupInputData' is a domain"
		$url = "https://login.microsoftonline.com/$LookupInputData/.well-known/openid-configuration"
	}
	else
	{
		Write-Log -Level INFO -Message "Input '$LookupInputData' is a tenant ID"
		$url = "https://login.microsoftonline.com/$LookupInputData/v2.0/.well-known/openid-configuration"
	}
	
	Write-Log -Level INFO -Message "Sending GET request for '$LookupInputData' - URL: '$url'"
	
	try
	{
		$response = Invoke-RestMethod -Uri $url -Method Get
		
		$tenantId = $response.issuer -replace 'https://sts.windows.net/', '' -replace 'https://login.microsoftonline.com/', '' -replace '/v2.0', '' -replace '/', ''
		
		Write-Log -Level INFO -Message "Extracted Tenant ID: '$tenantId' from GET response"
		
		if ([string]::IsNullOrWhiteSpace($tenantId))
		{
			Write-Log -Level ERROR -Message "Tenant ID could not be extracted from the response."
			return $null
		}
		
		return $tenantId
	}
	catch [System.Net.WebException] {
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