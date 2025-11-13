rule EICAR_Test_File
{
    meta:
        author = "EICAR"
        severity = "critical"
        description = "EICAR Standard Antivirus Test File - harmless test string"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii
        $eicar_alt1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" wide
        $eicar_alt2 = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii
    condition:
        any of ($eicar*)
}
