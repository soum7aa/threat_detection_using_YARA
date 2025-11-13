rule Packed_UPX
{
    meta:
        author = "Demo"
        severity = "medium"
        description = "UPX-packed binary indicator"
    strings:
        $upx1 = "UPX!" ascii
        $upx2 = "UPX0" ascii
        $upx3 = "UPX1" ascii
    condition:
        2 of ($upx*)
}
