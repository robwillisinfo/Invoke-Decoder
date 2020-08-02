 <#
.SYNOPSIS

Invoke-Decoder is a menu driven script that can be used to decode/deobfuscate malware sample strings.

By default, all output will be saved to the running directory /Invoke-Decoder.

This script can be used to decode the following types of strings:
- base64
- base64 and compressed
- base64 and gzip compressed
- base64 and xor

There is also an additional option to strip out non-printable and extended ASCII characters in
attempt to make decoded binaries a little more human readable.

.DESCRIPTION

Author: Rob Willis (admin@robwillis.info)
Post: http://robwillis.info/2020/08/invoke-decoder-a-powershell-script-to-decode-deobfuscate-malware-samples/

.EXAMPLE

PS> PowerShell.exe -Exec Bypass .\Invoke-Decoder.ps1

.NOTES

The script is menu driven, just run it and select a menu option.

#>

[CmdletBinding()] Param() 

# Begin functions

Function Pause {
	Write-Host -NoNewLine "| Press any key to continue...`n"
	$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

Function loadSample {
    Write-Host "+----------------------------------------------------------------------------"
    Write-Host "| Is the sample a file or string?"
    Write-Host "|"
    Write-Host "| F = File"
    Write-Host "| S = String"
    Write-Host "| M = Return to main menu"
    Write-Host "|"
    $sampleType = Read-Host -Prompt "| Selection"
    if($sampleType -like "F"){ 
        # Sample is a file
        Write-Host "|"
        $sampleFile = Read-Host -Prompt "| Please enter the file location"
        if($sampleFile -eq $null -OR $sampleFile.Length -eq 0) {
            Write-Host "|"
            Write-Host "| No path was specified!"
            Write-Host "|"
            Pause
            loadSample
        }
        $fileCheck = Test-Path $sampleFile
        if ($fileCheck -eq $False){
            Write-Host "|"
            Write-Host "| That file does not appear to exist!"
            Write-Host "|"
            Pause
            # Return to start of function
            loadSample
        } else {
            # Sample exists, load the contents
            $Global:sample = Get-Content $sampleFile
            # Update the length
            $Global:sampleSize = $sample.Length
            # Check to see if the sample is null or has a length of 
            Write-Host "|"
            Write-Host "| Sample size: $sampleSize"
            if ($sampleSize -eq $null -OR $sampleSize -eq "0") {
                Write-Host "|"
                Write-Host "| Something went wrong, the sample size is: $sampleSize"
                Write-Host "|"
                Write-Host "| Please select one of the following:"
                Write-Host "| R = Retry"
                Write-Host "| M = Main menu"
                Write-Host "|"
                $sampleSizeInput = Read-Host "| What would you like to do?"
                if($sampleSizeInput -like "R"){ loadSample }    
                if($sampleSizeInput -like "M"){ Menu }    
                else { Menu }
            }
            Write-Host "|"
            Write-Host "| Sample appears to have loaded successfully!"
            Write-Host "|"
            Pause
        }
     }    
    if($sampleType -like "S"){
        # Sample is a string
        # Get the string to decode
        Write-Host "|"
        $string = Read-Host -Prompt "| Please enter a sample string"
        # Create a timpstamp, this will be used filenames later
        $Global:timeStamp = Get-Date -Format "MMM-dd-yyyy-HH-mm"
        # Check to see if a string was entered
        If ($string.length -eq $null -OR $string.length -eq "0") {
            Write-Host "|"
            Write-Host "| Warning: It does not appear a string was entered!"
            Write-Host "|"
            Pause
            loadSample
        }
        # Check the length, read-host seems to have an input limit of 8190 characters
        If ($string.length -gt "8189") {
            Write-Host "+----------------------------------------------------------------------------"
            Write-Host "| WARNING: This string appears to be very large, saving to disk to avoid truncation..."
            Write-Host "| Max in memory sample size: 8190"
            Write-Host "| Current sample size: $(($string).length)"
            Write-Host "|"
            Write-Host "| Creating a sample file and opening notepad..."
            $sampleFile = $outputDir + "Invoke-Decoder-Sample-" + $Global:timeStamp + ".txt"
            Write-Host "| Sample file path: $sampleFile"
            New-Item -ItemType File -Force -Path $sampleFile | Out-Null
            Write-Host "| Please save the sample string in notepad."
            Write-Host "|"
            notepad $sampleFile
            # Pause so the user can save the input
            Pause
            # Get the content of the sample file
            $Global:sample = Get-Content $sampleFile
            # Get the length of the sample
            $Global:sampleSize = $sample.Length
            # Check to see if the sample is null or has a length of 
            Write-Host "|" 
            Write-Host "| Sample size: $sampleSize"
            if ($sampleSize -eq $null -OR $sampleSize -eq "0") {
                Write-Host "|"
                Write-Host "| Something went wrong, the sample size is: $sampleSize"
                Write-Host "|"
                Write-Host "| Please select one of the following:"
                Write-Host "| R = Retry"
                Write-Host "| M = Main menu"
                Write-Host "|"
                $sampleSizeInput = Read-Host "| What would you like to do?"
                if($sampleSizeInput -like "R"){ loadSample }    
                if($sampleSizeInput -like "M"){ Menu }    
                else { Menu }
            }
            # Everything appears to be ok, return to menu
            Write-Host "| Sample appears to have loaded successfully!"
            Write-Host "|"
            Pause
        } else {
            # The string was not larger than 8190, use the string as the sample
            $Global:sample = $string
            # Update the length
            $Global:sampleSize = $sample.Length
            # Save the sample to a file for review later
            Write-Host "|"
            Write-Host "| Saving sample to file..."
            $sampleFile = $outputDir + "Invoke-Decoder-Sample-" + $Global:timeStamp + ".txt"
            Write-Host "| Sample file path: $sampleFile"
            New-Item -ItemType File -Force -Path $sampleFile | Out-Null
            $sample | Out-File $sampleFile
            Write-Host "| Sample size: $sampleSize"
            Write-Host "|"
            Write-Host "| Sample appears to have loaded successfully!"
            Write-Host "|"
            Pause
        }
    }  
    if($sampleType -like "M"){
        Menu
    } 
    Menu
}

Function viewSample {
    # Check to see if a sample is loaded
    isSampleLoaded
    # View the sample
    Write-Host "+----------------------------------------------------------------------------"
    Write-Host "| Begin sample string"
    Write-Host "+----------------------------------------------------------------------------"
    $sample
    Write-Host "+----------------------------------------------------------------------------"
    Write-Host "| End sample string"
    Write-Host "+----------------------------------------------------------------------------"
    Pause
    Menu
}

function isSampleLoaded {
    # Check to see if a sample was loaded and run the loadSample function if not
    Write-Host "+----------------------------------------------------------------------------"
    Write-Host "| Checking to see if a sample is loaded..."
    If($sample -eq $null -OR $sample -eq "0")
    {
        # No sample loaded
        Write-Host "| It does not appear that a sample was loaded, loading sample..."
        loadSample
    } 
}

# base64 decoder - Option 1
Function b64Decode {
    # Check to see if a sample is loaded by running the isSampleLoaded function
    isSampleLoaded
    # Basic base64 decode
    Write-Host "+----------------------------------------------------------------------------"
    Write-Host "| Decoding base64 sample..."
    Write-Host "|"
    $decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("$sample"))
    # Create the log file
    $b64Log = $outputDir + "Invoke-Decoder-base64-decoded-" + $timeStamp + ".txt"
    Write-Host "| Output file: $b64Log"
    # Write the log
    $decoded | out-file $b64Log
    # Open the log for the user to review
    notepad $b64Log
    Write-Host "|"
    Pause
	Menu
}

# base64 and compressed string - Option 2
Function base64DecodeDecomp {
    # Check to see if a sample is loaded by running the isSampleLoaded function
    isSampleLoaded
    Write-Host "+----------------------------------------------------------------------------"
    Write-Host "| Decoding base64 and decompressing sample..."
    Write-Host "|"
    # Basic base64 decode
    $decoded = [System.Convert]::FromBase64String("$sample")
    # Decompress the decoded string
    # Borrowed from Nishang - Invoke-Decode - https://github.com/samratashok/nishang/blob/master/Utility/Invoke-Decode.ps1
    $ms = New-Object System.IO.MemoryStream
    $ms.Write($decoded, 0, $decoded.Length)
    $ms.Seek(0,0) | Out-Null
    $cs = New-Object System.IO.Compression.DeflateStream ($ms, [System.IO.Compression.CompressionMode]::Decompress)
    $sr = New-Object System.IO.StreamReader($cs)
    $result = $sr.readtoend()
    # Create the log file and open it in notepad
    $base64DecodeDecompLog = $outputDir + "Invoke-Decoder-base64-decoded-decompressed-" + $timeStamp + ".txt"
    Write-Host "| Output file: $base64DecodeDecompLog"
    $result | out-file $base64DecodeDecompLog
    notepad $base64DecodeDecompLog
    Write-Host "|"
    Pause
	Menu
}

# base64 and gzipped string - Option 3
Function base64DecodeDecompGzip {
    # Check to see if a sample is loaded by running the isSampleLoaded function
    isSampleLoaded
    Write-Host "+----------------------------------------------------------------------------"
    Write-Host "| Decoding base64 and decompressing (gzip) sample..."
    Write-Host "|"
    # Basic base64 decode
    $decoded = [System.Convert]::FromBase64String("$sample")
    $ms = New-Object System.IO.MemoryStream
    $ms.Write($decoded, 0, $decoded.Length)
    $ms.Seek(0,0) | Out-Null
    $cs = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
    $sr = New-Object System.IO.StreamReader($cs)
    $result = $sr.readtoend()
    # Create the log file and open it in notepad
    $base64DecodeDecompGzipLog = $outputDir + "Invoke-Decoder-base64-decoded-decompressed-gzip-" + $timeStamp + ".txt"
    Write-Host "| Output file: $base64DecodeDecompGzipLog"
    $result | out-file $base64DecodeDecompGzipLog
    notepad $base64DecodeDecompGzipLog
    Write-Host "|"
    Pause
	Menu
}

Function base64Xor {
    # Check to see if a sample is loaded by running the isSampleLoaded function
    isSampleLoaded
    Write-Host "+----------------------------------------------------------------------------"
    Write-Host "| Decoding base64 and xor'd sample..."
    Write-Host "|"
    $xorKey = Read-Host -Prompt "| Please enter the xor key to decode with"
    If ($xorKey -eq $null) {
        Write-Host "| No key was entered."
        Pause
        # Return to menu
        Menu
    }
    $bytes = [Convert]::FromBase64String($sample)
                
    # XOR “encryption”
    for($counter = 0; $counter -lt $bytes.Length; $counter++)
    {
        $bytes[$counter] = $bytes[$counter] -bxor $xorKey
    }
    $result = [System.Text.Encoding]::ASCII.GetString($bytes)
    
    # Create the log file and open it in notepad
    $base64XorLog = $outputDir + "Invoke-Decoder-base64-xor-" + $timeStamp + ".txt"
    Write-Host "| Output file: $base64XorLog"
    $result | out-file $base64XorLog
    notepad $base64XorLog
    Write-Host "|"
    Pause
    Menu
}

# Show current settings- Option 4
Function removeNonPrintableCharacters {
    # Check to see if a sample is loaded by running the isSampleLoaded function
    isSampleLoaded
    Write-Host "+----------------------------------------------------------------------------"
    Write-Host "| Removing non printable and extended ASCII characters from sample..."
    # The entire list of 
    $nonPrintableCharacters = @(# Non printable ASCII characters - Leave out \x0A (Line feed), \x0D (Carriage return)
                                "\x00","\x01","\x02","\x03","\x04","\x05","\x06","\x07","\x08","\x09","\x0B","\x0C","\x0E","\x0F",
                                "\x10","\x11","\x12","\x13","\x14","\x15","\x16","\x17","\x18","\x19","\x1A","\x1B","\x1C","\x1D","\x1E","\x1F",
                                "\x80","\x81","\x82","\x83","\x84","\x85","\x86","\x87","\x88","\x89","\x8A","\x8B","\x8C","\x8D","\x8E","\x8F",
                                "\x90","\x91","\x92","\x93","\x94","\x95","\x96","\x97","\x98","\x99","\x9A","\x9B","\x9C","\x9D","\x9E","\x9F",
                                # Extended ASCII range
                                "\xA0","\xA1","\xA2","\xA3","\xA4","\xA5","\xA6","\xA7","\xA8","\xA9","\xAA","\xAB","\xAC","\xAD","\xAE","\xAF",
                                "\xB0","\xB1","\xB2","\xB3","\xB4","\xB5","\xB6","\xB7","\xB8","\xB9","\xBA","\xBB","\xBC","\xBD","\xBE","\xBF",
                                "\xC0","\xC1","\xC2","\xC3","\xC4","\xC5","\xC6","\xC7","\xC8","\xC9","\xCA","\xCB","\xCC","\xCD","\xCE","\xCF",
                                "\xD0","\xD1","\xD2","\xD3","\xD4","\xD5","\xD6","\xD7","\xD8","\xD9","\xDA","\xDB","\xDC","\xDD","\xDE","\xDF",
                                "\xE0","\xE1","\xE2","\xE3","\xE4","\xE5","\xE6","\xE7","\xE8","\xE9","\xEA","\xEB","\xEC","\xED","\xEE","\xEF",
                                "\xF0","\xF1","\xF2","\xF3","\xF4","\xF5","\xF6","\xF7","\xF8","\xF9","\xFA","\xFB","\xFC","\xFD","\xFE","\xFF"
    )
    # Strip the characters
    foreach ($nonPrintableCharacter in $nonPrintableCharacters) {
        Write-Verbose "Removing $NonPrintableChar"
        $result = $result -replace $nonPrintableCharacter,""
    }
    $NonPrintableAsciiCharacterLog = $outputDir + "Invoke-Decoder-NonPrintable-ASCII-Removed-" + $timeStamp + ".txt"
    Write-Host "|"
    Write-Host "| Output file: $NonPrintableAsciiCharacterLog"
    Write-Host "|"
    # Output to ASCII encoding for readability
    $result | out-file -encoding ASCII $NonPrintableAsciiCharacterLog
    notepad $NonPrintableAsciiCharacterLog
    Pause
	Menu
}

Function openOutputDir {
    explorer.exe $outputDir
    Menu
}

# Quit
Function quit {
	exit
}

# Menu
Function Menu {
	# Clear the screen
    Clear
    # Windows Defender real-time protection check
    $windowsDefenderStatus = (Get-MpComputerStatus).RealTimeProtectionEnabled
    If($windowsDefenderStatus -eq "True") {
        $windowsDefenderStatus = "True (Warning: This can interfere with decoding malware samples!)"
    }
    # Menu/User input
    Write-Host "+----------------------------------------------------------------------------"
    Write-Host "|"
    Write-Host "| Invoke-Decoder v0.1"
    Write-Host "|"
    Write-Host "+----------------------------------------------------------------------------"
    Write-Host "| Windows Defender Real-time Protection status: $windowsDefenderStatus"
    Write-Host "|"
    Write-Host "| Output directory: $outputDir"
    Write-Host "| Current sample size: $sampleSize"
    Write-Host "| Current sample timestamp: $timeStamp"
    Write-Host "+----------------------------------------------------------------------------"
    Write-Host "| Please select an option:"
    Write-Host "|"
    Write-Host "| D = To open the output Directory"
    Write-Host "| L = To Load a sample string"
    Write-Host "| V = To View the sample string"
    Write-Host "|"
	Write-Host "| 1 = base64 decode"
	Write-Host "| 2 = base64 decode and decompress"
    Write-Host "| 3 = base64 decode and gzip decompress"
    Write-Host "| 4 = base64 decode and xor"
    Write-Host "| R = Remove non-printable ASCII characters"	
    Write-Host "|"
	Write-Host "| Q = Quit"
    Write-Host "+----------------------------------------------------------------------------"
    $input = Read-Host -Prompt "| Selection"
    if("$input" -like "D"){ openOutputDir }
    if("$input" -like "L"){ loadSample }    
    if("$input" -like "V"){ viewSample }    
	if("$input" -like "1"){ b64Decode }
	if("$input" -like "2"){ base64DecodeDecomp }
    if("$input" -like "3"){ base64DecodeDecompGzip }
    if("$input" -like "4"){ base64Xor }
	if("$input" -like "R"){ removeNonPrintableCharacters }
	if("$input" -like "Q"){ quit }
	else { Menu }
}
# End functions

# Begin script

# Directory to save output
$outputDir = "Invoke-Decoder"
# Get the current directory
$currentDirectory = Get-Location
Write-Verbose "Current directory: $currentDirectory.path"
# Build the output directory
$outputDir = $currentDirectory.path + "\" + $outputDir + "\"
Write-Verbose "Output directory that will be used to save data: $outputDir"
# Check to see if the outputDir exists and create it if it does not
If(!(test-path $outputDir))
{
    # The directory did not exist, create it  
    New-Item -ItemType Directory -Force -Path $outputDir
}
# Run the main menu
Menu
