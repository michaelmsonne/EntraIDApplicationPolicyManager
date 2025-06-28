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