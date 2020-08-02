# Invoke-Decoder
Invoke-Decoder – A PowerShell script to decode/deobfuscate malware samples

![Invoke-Decoder](https://github.com/robwillisinfo/Invoke-Decoder/blob/master/Invoke-Decoder.PNG)

Invoke-Decoder is a menu driven script that can decode the following types of payloads at this time:
* base64
* base64 and compressed
* base64 and gzip compressed
* base64 and xor

There is also an additional option to strip out non-printable and extended ASCII characters in attempt to make decoded binaries a little more human readable.

Usage:  
PS> PowerShell.exe -Exec Bypass .\Invoke-Decoder.ps1
