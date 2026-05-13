rule Windows_Loader_PhantomStealer_01 {
    meta:
        description = "Phantom Stealer NativeAOT pdh.dll Sideloading Loader"
        author      = "Dark Atlas; @ELJoOker"
        date        = "2026-05-05"
        reference   = "https://blog-wp.darkatlas.io/2026/05/13/phantom-stealer-analysis-inside-the-two-layer-attack-chain-hidden-behind-a-windows-dll/"
        hash        = "D8A05DEEFE97C6BBE1E083E9D8A182E6B6E5FBC77AF483D2CDEF0B4CADEC22CE"

    strings:
        $s1         = "DotNetRuntimeDebugHeader" ascii
        $s2         = "PdhAddCounterA" ascii
        $s3         = "PdhGetCounterInfoA" ascii

    condition:
        uint16(0) == 0x5A4D and
        uint16(uint32(0x3C) + 0x18) == 0x020B and
        (
            ($s1 and $s2 and $s3) or
            ($s1 and $s2)
        )
}
