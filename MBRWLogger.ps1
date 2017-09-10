param
(
	[string]$Continuous = 0,
	[int]$PickupVerbose = 0,
	[int]$DisplayWait   = 10,
	[string]$MBRWLogFile
)
<#	
	.NOTES
	===========================================================================
	 Created on:   	3-April-17
	 Created by:   	Andrew Probert
	 Organization: 	Malwarebytes
	 Version:     	
	===========================================================================
	.DESCRIPTION
		This script reads the Malwarebytes Anti-Malware local activity log, 
		filters the input, then writes appropriately named files containing 
		Anti-Malware formats to the folder .\ProgramData\"Malwarebytes' Anti-Malware"\Logs 
		which is monitored by the Managed Client 'sccomm' process.  
		
		Inputs:   MBAMSERVICE.Log
		Outputs:  PROTECTION-LOG-yyyy-mm-dd-MBRW-ThreatLog.txt
				  PROTECTION-LOG-yyyy-mm-dd-MBRW-SystemLog.txt
				  MBRWLogger.XML
				  MBRWLoggerInstall.Log
				  MBRWLoggerUninstall.Log
		
		About every minute 'sccomm' picks up files and posts them to the clientservices
		url at 18457.  This can be observed by the files being renamed from 
		PROTECTION-LOG to ARCHIVED-PROTECTION-LOG; entries written in the 'sccomm.txt' logfile; and 
		'batch processing' messsages in the management console's log.
		
		A checkpoint file 'MBRWLogger.xml' is used to keep
		track of last record read, so that messages are not duplicated when the
		logger is restarted. The files is in .\ProgramData\MalwarebytesARW\MBAMService\logs 
		It also checks for logfile deletion or replacement. Note, for testing the MBRWLogger.XML file 
		can be deleted, to force a reread of a whole logfile.
		
		INSTALLATION AND MANUAL RUN
		
		Copy this script to any location.
		
		'Run as administrator', to ensure that the folders can be read/written.
		Note, With READ/WRITE permissions to the folders, it doesn't need any special privilege.
		
		No pre-configuration is necessary, the script uses environment variables to find ProgramData path.
		
		The script can be run from the Windows CMD shell or PowerShell, in foreground.  Write-Host commands
		provide information about processing.  The script defaults to running once.
		
		-Continous   	is the default setting in seconds, for a delay/repeat loop 
		         0    	the script runs once and terminates         i
				10   	would repeat pickup every 10 seconds.  This could be used for testing/demonstration
				
		-PickupVerbose	Default 0.  When set to 1, it picks up most MBARW activity messages and sends them to 
						the System Log in the console.  For use when testing.
						
		-DisplayWait    Default 10 seconds.  Useful when running in foreground, to give time to see results.				
						
		-MBRWLogFile xx	Default path to MBSERVICE.LOG is used.  When set to a full filepath, it reads an
						alternative log.  Useful for testing.  Note:  A change of logfile will be automatically
						detected, from MBRWLogger.XML and a full read will be done on first run.

		INSTALLATION AND AUTOMATED Run

		An installation script is separately provided, to add a task to the Windows 'Task Scheduler' to run this
		script periodically, in background, using the SYSTEM account.
						
		FILTERING & FORMATTING
		
		The Anti-Ransomware log messages are verbose, so a set of rules have been created to filter them, down to:
		Threat Log		There is one key message, only, for a Threat detection
		System Log		There are many potentially useful messages.  The criteria used were, Is this record useful
						to determine if Anti-Ransomware is running; versioning; and what happend if a clean occurred?

		Dates are parsed and rewritten
		Threat Log message is set with ThreatName: "ANTIRANSOMWARE.Behavioural.Detection"
		System Log Message is formatted:  		   "MBRW: messagelevel: message [filename]"

		One message is promoted to FATAL, if the Keystone registration process fail and the user is unprotected.

Changes
1.5 2017-04-03
    Added test for "ARW_ACTION_ALLOW" and suppress Threat Log, as this is informational for whitelist/signature check.

#>

function Status-New
{
	# Status XML Object to store information about last line read from log/last run
	# Restarts from last object. Does a full run if replaced MBAMSERVICE.LOG is detected
	# Delete MBRWLogger.XML to reset/reprocess all log entries
	param
	(
		[DateTime]$LastLogPickup,[DateTime]$LogStartDate,[DateTime]$LogEndDate,
		[int64]$LogLastObject,[String]$LogLastStatus
	)
	
	$xmlWriter = New-Object -ErrorAction Stop System.XMl.XmlTextWriter($MBRWLogFileXML, $Null)
		$xmlWriter.Formatting = 'Indented'
		$xmlWriter.Indentation = 1
		$XmlWriter.IndentChar = "`t"
	$xmlWriter.WriteStartDocument()
	$xmlWriter.WriteComment('MBRW-B Status')
	$xmlWriter.WriteStartElement('Status')
		$XmlWriter.WriteAttributeString('LogLastPickup', $LastLogPickup)
			$XmlWriter.WriteElementString('LogStartDate', $LogStartDate)
			$XmlWriter.WriteElementString('LogEndDate', $LogEndDate)
			$XmlWriter.WriteElementString('LogLastObject', $LogLastObject)
			$XmlWriter.WriteElementString('LogLastStatus', $LogLastStatus)
	$xmlWriter.WriteEndElement()
	$xmlWriter.WriteEndDocument()
	$xmlWriter.Flush()
	$xmlWriter.Close()
}

function InLogDate-Convert {
	# Converts MBAR-B logfile's date and time fields to standard [DateTime] format, then to 
	# date [string] for MBAM/SCCOMM pickup. Returns both in an array
	param
	(
		[parameter(Mandatory = $true)][string]$DateString,
		[parameter(Mandatory = $true)][string]$TimeString
	)
	# Concatenate date and time strings and convert to utc
	$DateTimeString = $DateString + $TimeString
	$DateTimeIn = [datetime]::ParseExact($DateTimeString, "MM/dd/yy HH:mm:ss.FFF", $null, "AssumeLocal")
	
	# Time offset is in HH:mm format, so strip semi-colon : by Regex into two parts in $matches array
	$DateTimeOffset = [String]$DateTimeIn.toString("zzz")
	$Splitdate = $DateTimeOffset -match "(.+):(..)"
	
	# Create date string compatible for MBAM log 
	$DateTimeOutStr = [String]$DateTimeIn.toString("yyyy\/MM\/dd HH:mm:ss ") + $matches[1] + $matches[2]
	Return $DateTimeOutStr, $DateTimeIn	
}

function Logline-Process
{
	# Analyse the Activity Log and output relevant recrods
	param
	([parameter(Mandatory = $true)][psobject]$Logline )
	
	$DateTime = InLogDate-Convert -DateString $LogLine.Date -TimeString $LogLine.Time
	
	If ($LogLine."File Name" -eq "ArwCleanupScheduler.cpp") {
		# This record is the key one for identifying a cleaning event
		$ThreatName = "ANTIRANSOMWARE.Behavioural.Detection"
		$Parse = $LogLine.Message -match '^Received a results callback from ARW SDK - ObjectPath = (.+), ActionTaken=(.+), Result = (.+), RebootRequired = (.+)'
        
        # Filter on ActionTaken and suppress records which have allow, as they are either signed or MEPS-whitelisted
        Write-Host $Matches[2]
        switch ($Matches[2])
        {
            "ARW_ACTION_ALLOW" {
                Write-Host "switch 1"
                break
                }
            "ARW_ACTION_ALLOW_MEPS" {
                Write-Host "switch 2"
                break
                }

            default
            {
    		    # Create Threat Log Record & write IMMEDIATELY		
    		    $LogThRec = "{0}`t{1}`t{2}`t{3}`t{4}`t{5}`t{6}`r`n" -f $DateTime[0], $env:COMPUTERNAME, "SYSTEM", "DETECTION", $Matches[1], $ThreatName, "QUARANTINE"

    		    $FilePart = $DateTime[1].toString("yyyy-MM-dd") + "-MBRW-ThreatLog"
    		    $ProtectionLogFile = $MBAMLogPath + "protection-log-" + $FilePart + ".txt";
    		    $LogThRec >  $ProtectionLogFile
    		    Write-Host $ProtectionLogFile
    		    Write-Host $LogThRec            
            }   
        }
	}
		
	##################################################################################
	# Filter the 'Activity Log' for significant messages
	##################################################################################
	switch ($LogLine."Log Level")
	{
		"Debug" {
			# Some Debug messages have JSON multiline with `n LF, do not allow these as they will hang on transfer.
			$Pickup = $false; Break }
		"ERROR" {
			# Log all Error Messages, unless suppressed further down.
			$Pickup = $true
			if ($LogLine."Message" -eq "Unable to retreive an installation token, unable to redeem with Keystone.")
			{
				######################################################################################
				# Promote to FATAL, as the user is unlicensed/unprotected
				######################################################################################
				$Pickup = $true
				$LogLine."Log Level" = "FATAL "
				break
			}
			if ($LogLine."Message" -like "Received a [403] response from Keystone*")
			{
				######################################################################################
				# Promote to FATAL, as the user is unlicensed/unprotected
				######################################################################################
				$Pickup = $true
				$LogLine."Log Level" = "FATAL "
				break
			}

			# Always drop these superfluous messages
			if ($LogLine.Message -like "{Thread*") 			{ $Pickup = $false }
			if ($LogLine."File Name" -eq "JSONUtilities.h") { $Pickup = $false }
			break }
		"WARNING"{
			$Pickup = $PickupVerbose
			if ($LogLine.Message -eq "Queue Thread initialization did not complete in time, continuing...") { $Pickup = $false }
			break
			}
		"INFO" {
			# Process using a Switch, as there are a lot of modules producing records
			$Pickup = $PickupVerbose
			switch ($LogLine."File Name")
			{
				"ARWCleanupScheduler.cpp" {
					# Cleaning messages come from this module.
					$Pickup = $true
					break
				}
				"ARWControllerImplHelper.cpp" {
					# Allow Started/Stopped messages 
					if ($LogLine.Message -like "Anti-Ransomware protection has*") { $Pickup = $true }
					# Log Exclusion activity, in case end-users are changing parameters
					if ($LogLine.Message -like "Successfully*") { $Pickup = $true }
					break
				}
				"CleanController.cpp" {
					$Pickup = $true
					# Generally allow, but drop the following superfluous message  
					if ($LogLine.Message -eq "Initialized CleanController") { $Pickup = $false }
					break
				}
				"QuarantineEngine.cpp" {
					# Show all quarantining actions.
					$Pickup = $true
					break
				}
				"ServiceControllerImplementation.cpp"
				{
					# Messages hidden, but show lines below for checking on versions/updates
					if ($LogLine.Message -like "Product Version*") { $Pickup = $true }
					if ($LogLine.Message -like "Product Code*") { $Pickup = $true }
					break
				}
				"LogController.cpp" {
					# Logging Started is always the 1st record, show it as an indicator of startup/restart
					$Pickup = $true
					break
				}
				"UpdateControllerImplHelper.cpp" {
					# Show the automatic 'Component update' processing messages, to know a client is updated 
					if ($LogLine.Message -like "A New version*") { $Pickup = $true }
					if ($LogLine.Message -like "Component Update Package:*") { $Pickup = $true }
					break
				}
				"wmain" {
					# Show messages when applying the update are from this module, used PickupVerbose setting 
					break
				}
				default { $Pickup = $PickupVerbose; break }
			}
		}
		default { $Pickup = $PickupVerbose; break }
		
	}
	if ($Pickup -eq $true)
		{
		# Create a System Log record
		$LogRec = "{0}`t{1}`t{2}`t{3}`tMBRW: {4} {5} [{6}]" -f $DateTime[0], $env:COMPUTERNAME, "SYSTEM", "MESSAGE", $LogLine."Log Level", $LogLine.Message, $LogLine."File Name"
		
		# Create a new file name for each day's records, from this record
		$FileDate = [string]$DateTime[1].toString("yyyy-MM-dd")  + "-MBRW-SystemLog"
		$ProtectionLogFile = $MBAMLogPath + "protection-log-" + $FileDate + ".txt";
		# Append to named logfile
		$LogRec >>  $ProtectionLogFile
		# Add CR/LF to record, for later display
		$LogRec += "`r`n"
		Return $LogRec
	}
}

########################################################################
#  MAIN BODY
#########################################################################
if ($MBRWLogFile -eq "")
{	
	$MBRWLogFile = $env:ProgramData + "\MalwarebytesARW\MBAMservice\logs\MBAMSERVICE.log"
}
# Set output paths using environment variables
$MBRWLogFileXML  = $env:ProgramData + "\MalwarebytesARW\MBAMservice\logs\MBRWLogger.xml"
$MBAMLogPath     = $env:ProgramData + "\Malwarebytes\Malwarebytes' Anti-Malware\Logs\"

Write-Host -Continuous = $Continuous seconds, 0 = one run
Write-Host -PickupVerbose is $PickupVerbose
Write-Host -DisplayWait is $DisplayWait
Write-Host -MBRWLogFile is $MBRWLogFile
Write-Host Last run checkpoint file is $MBRWLogFileXML
Write-Host 
Write-Host
$Pickup = $false; # Initialise to boolean, for later use.
while ($true)  
{
	# Track start of this run
	$LogPickup 		= [System.DateTime]::Now; $LogLastStatus
	$LogRecs 		= ""; # Blank output
	$LogLastStatus 	= ""
	# Read last run status	
	try
	{
		[xml]$StatusLast = Get-Content -ErrorAction Stop -Path $MBRWLogFileXML
		$LastLogStartDate = [System.DateTime]$StatusLast.Status.LogStartDate
		$LastObjectNum = [int64]$StatusLast.Status.LogLastObject
	}
	Catch
	{
		$LogLastStatus = "MBRWLogger.xml not opened, start a new run`r`n"
		$LastObjectNum = [int64]0
		$LastLogStartDate = [System.DateTime]0
	}
	
	# Read MBAMSERVICE.LOG into array.  Tab delimiters split into variables which are identified in headers
	Try
	{  $LogLines = Import-Csv -ErrorAction Stop -Delimiter "`t" -Path $MBRWLogFile }
	Catch {
		$LastLogStatus = "MBAMSERVICE.LOG could not be read.  Nothing to do`r`n"
		$LastLogStatus += $Error[0].Exception.Message
		$Status = Status-New -LastLogPickup $LogPickup -LogStartDate 0 -LogEndDate 0 -LogLastObject 0 -LogLastStatus $Error[0].Exception.Message

		if ($Continuous -gt 0) {
			sleep -Seconds $Continuous
			continue; # Jump to start of While
		} else { break }
	}
	
	# Read 1st and last lines for Start and End Date + Time and convert to array with [0] MBAM/SCCOM format and [1] [DateTime] 
	$LogStartDate = InLogDate-Convert -DateString $LogLines[0].Date -TimeString $LogLines[0].Time
	$LogEndDate   = InLogDate-Convert -DateString $LogLines[-1].Date -TimeString $LogLines[-1].Time
	
	# If start from StatusXML matches, a logfile is being continued otherwise a different 
	if ($LastLogStartDate -eq $LogStartDate[0])
	{ $LogLastStatus += "Processing existing logfile, StartDate matched LastStatus from MBRWLogger.xml`r`n" }
	else {
		$LogLastStatus += "`Processing new logfile, StartDate did not match LastStatus from MBRWLogger.xml`r`n"
		$LastObjectNum = [int64]0
	}
	
	$j = $LogLines.LongLength
	# Loop doesn't run if there are no new records
	if ($LastObjectNum -eq $j)
	{ $LogLastStatus += "No new data to process, LastObjectNum is {0} Logfile has {1:G} objects`r`n" -f $LastObjectNum, $j }
	else
	{
		# Process into Threat and System Log entries
		# Since Arrays are base zero, LastObjectNum can be used for index to 1st new item.
		$LogLastStatus += "New data to process, LastObjectNum is {0} Logfile has {1:G} objects`r`n" -f $LastObjectNum, $j
		$i = $LastObjectNum
		$Log
		While ($i -lt $j)
		{
			$LogLine = $LogLines[$i]
			$LogRecs += Logline-Process ($Logline)
			$i++
		}
		# Display log records output
		Write-Host $LogRecs
		Write-Host ""
		Write-Host ""
	
	}
	# Create new Status object. Object count excludes json Data lines which aggregate as single line as they have NEWLINE and no CR
	[xml]$StatusXML = Status-New -LastLogPickup $LogPickup -LogStartDate $LogStartDate[0] -LogEndDate $LogEndDate[0] -LogLastObject $LogLines.LongLength -LogLastStatus $LogLastStatus
	Type $MBRWLogFileXML
	
	# For debugging, uncomment lines below
	# Write-Host "Press any key to continue ..."
	# $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
	
	
	if ($Continuous -gt 0)
	{
		sleep -Seconds $Continuous
	} else {break}
}
# Wait a bit, so output can be seen in foreground, if "Run only when user is logged in" is used in scheduled tasks
Sleep -seconds $DisplayWait
Write-Host Exited
exit 0