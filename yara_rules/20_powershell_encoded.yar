rule Suspicious_PowerShell_EncodedCommand
{
    meta:
        author = "Demo"
        severity = "high"
        description = "PowerShell encoded command usage often seen in attacks"
    strings:
        $ps1 = "powershell" nocase
        $ps2 = "-enc" nocase
        $ps3 = "-encodedcommand" nocase
        $b64 = /[A-Za-z0-9+\/]{40,}={0,2}/
    condition:
        any of ($ps*) and $b64
}
