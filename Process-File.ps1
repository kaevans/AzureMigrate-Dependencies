#Requires -Version 7.3
<#
.SYNOPSIS
    A script that performs some task.

.DESCRIPTION
    A detailed description of what the script does.

.PARAMETER ServerListFilePath
    The path to the file containing a list of servers, each server name on a new line.

.PARAMETER InputFilePath
    The path to the input file.

.PARAMETER OutputFilePath
    The path to the output file.



.EXAMPLE
    .\\MyScript.ps1 -ServerListFile c:\\serverList.csv -InputFile C:\\input.csv -OutputFile C:\\output.csv

    Runs the script with the specified input and output files.
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_})]    
    [string]$ServerListFilePath,

    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_})]
    [string]$InputFilePath,

    [Parameter(Mandatory=$true)]    
    [string]$OutputFilePath

)

#region Variables

$ErrorActionPreference = 'Stop'

#endregion

#region Functions

function Get-ServerDependencies(
    [Parameter(Mandatory=$true)]$inputServer, 
    [Parameter(Mandatory=$true)]$inputCSV, 
    [Parameter(Mandatory=$true)]$outputCSV)
{

    Write-Verbose "Server: $($inputServer.'Server Name') Server IP: $($inputServer.'Server IP') Azure Server IP: $($inputServer.'Azure Server IP')"

    $reader = [System.IO.File]::OpenText($inputCSV)
    try {
        # Read the header line
        $inputLine = $reader.ReadLine()
        
        # Read the rest of the lines
        for() {
            $inputLine = $reader.ReadLine()
            if ($null -eq $inputLine) { break }
                    
            Write-Verbose $inputLine
    
            #Read the CSV line from a string, providing the original header
            $csvObjects = $inputLine | ConvertFrom-Csv -Header "Time slot","Source server name","Source IP","Source application","Source process","Destination server name","Destination IP","Destination application","Destination process","Destination port"
            if($null -ne $csvObjects) {
                $sourceServerName = $csvObjects.'Source server name'
                $sourceIP = $csvObjects.'Source IP'
                $destinationServerName = $csvObjects.'Destination server name'
                $destinationIP = $csvObjects.'Destination IP'
                $destinationPort = $csvObjects.'Destination port'
            }
            
            
            #Check to see if the server name in the dependencies file matches the current server name
            if($sourceServerName -ne $inputServer.'ServerName' -and $destinationServerName -ne $inputServer.'ServerName')
            {
                Write-Verbose "Source server $sourceServerName and Destination server $destinationServerName do not match the current server name $($inputServer.'ServerName'). Skipping the entry"
                continue
            }
                        
            if($sourceIP -eq $destinationIP)
            {            
                Write-Verbose "Source IP $sourceIP and Destination IP $destinationIP are same. Skipping the entry"
                continue
            }
    
            if($sourceIP.Contains(":") -or $destinationIP.Contains(":"))
            {
                Write-Verbose "Source IP $sourceIP or Destination IP $destinationIP are IPv6. Skipping the entry"
                continue
            }
    
            $ruleType = Get-RuleType -currentServerName $inputServer.'ServerName' -sourceServerName $sourceServerName -destinationServerName $destinationServerName

            $outputLine = $inputServer.'ServerName', $ruleType, $inputServer.'CurrentIP',$inputServer.'AzureIP',$sourceServerName, $sourceIP, $destinationServerName, $destinationIP, $destinationPort -join ","
            Write-Verbose "Adding entry: $outputLine"
            Add-Content -Path $outputCSV -Value $outputLine        
        }        
    
    }
    finally {
        $reader.Close()
    }    
}

function Get-ServerList($ServerListFile)
{
    $serverList = Import-Csv -Path $ServerListFile
    return $serverList
}

function Write-OutputHeader($outputCSV)
{
    #Write the header to the output file
    $outputHeader = "Server name","RuleType","Current Server IP", "Azure Server IP", "Source server name", "Source IP","Destination server name","Destination IP","Destination port" -join ","    
    Set-Content -Path $outputCSV -Value $outputHeader
}

function Get-RuleType($currentServerName, $sourceServerName, $destinationServerName)
{
    #If current server name matches sourceservername then it is an outbound rule
    #If current server name matches destination server name then it is an inbound rule
    $ruleType = "Outbound"
    if($currentServerName -eq $destinationServerName)
    {
        $ruleType = "Inbound"
    }

    return $ruleType
}

#endregion

#region Main

Write-Verbose "Starting the script"

$serverList = Get-ServerList -ServerListFile "C:\code\AzureMigrate-Dependencies\serverList.csv"

#Write the header to the output file
Write-Verbose "Writing the header to the output file"
Write-OutputHeader -outputCSV $OutputFilePath

foreach($server in $serverList)
{
    Get-ServerDependencies -inputServer $server -InputCSV $InputFilePath -outputCSV $OutputFilePath
}


Write-Verbose "Ending the script"

#endregion