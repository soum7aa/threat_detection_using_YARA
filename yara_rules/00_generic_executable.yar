rule Generic_PE_Executable
{
    meta:
        author = "Demo"
        severity = "low"
        description = "Matches generic PE executables by 'MZ' header (for testing pipeline)"
    strings:
        $mz = { 4D 5A }  // "MZ"
    condition:
        uint16(0) == 0x5A4D or $mz
}
