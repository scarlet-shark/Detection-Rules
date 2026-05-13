rule Windows_Stealer_PhantomStealer {
    meta:
        description = "Phantom Softwares Stealer .NET Payload (Phantom Stealer v3.5.x)"
        author      = "Dark Atlas; @ELJoOker"
        date        = "2026-05-05"
        reference   = "https://blog-wp.darkatlas.io/2026/05/13/phantom-stealer-analysis-inside-the-two-layer-attack-chain-hidden-behind-a-windows-dll/"
        hash        = "d2f509efbdb1d4ae68216807648ea34ba8af5778e1626fc67085b832eebfdc53"

    strings:
        $s1         = "Phantom stealer" wide
        $s2         = "phantomsoftwares.site" wide
        $s3         = "Initiating self-destruct" wide
        $s4         = "app_bound_encrypted_key" wide
        $s5         = "ClipperThread" wide
        $s6         = "HeavensGate" ascii
        $s7         = "DecryptByteDesCbc" ascii
        $s8         = "Oldphantomoftheopera" wide
        $s9         = "P97KH92W6NXUNLKT9UBI" wide

    condition:
        uint16(0) == 0x5A4D and
        uint16(uint32(0x3C) + 0x18) == 0x010B and
        (
            ($s1 and $s2) or
            ($s1 and $s3 and $s6) or
            ($s2 and $s7 and $s5) or
            ($s9 and $s6 and $s4 and $s8)
        )
}
