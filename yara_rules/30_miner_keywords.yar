rule CryptoMiner_Known_Keywords
{
    meta:
        author = "Demo"
        severity = "medium"
        description = "Common miner keywords"
    strings:
        $a1 = "xmrig" nocase
        $a2 = "cryptonight" nocase
        $a3 = "stratum+tcp" nocase
        $a4 = "ethash" nocase
    condition:
        1 of ($a*)
}
