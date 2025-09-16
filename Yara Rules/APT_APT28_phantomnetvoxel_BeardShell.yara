rule APT_APT28_phantomnetvoxel_BeardShell: STABLE {
    meta:
        description = "Detects BeardShell malware."
        author = "ekoia.io"
        source = "Sekoia.io"
        creation_date = "2025-02-25"
        date = "2025-02-25"
        classification = "TLP:GREEN"
        hash = "5d938b4316421a2caf7e2e0121b36459"
        reference = "https://blog.sekoia.io/apt28-operation-phantom-net-voxel/"
        malware = "BeardShell"
        intrusion_set = "APT28"           
        tags = "APT28, BeardShell"

    strings:
        $rtti1 = "@Pwrshl"
        $rtti2 = "$WinHttpWrapper@"
        $CLSID_CorRuntimeHost = {23 67 2F CB 3A AB D2 11 9C 40 00 C0 4F A3 0A 3E}
        $NetWkstaUserGetInfo = "NetWkstaUserGetInfo"
        $GetCurrentHwProfileW = "GetCurrentHwProfileW"
        $XOR_decryption = {50 88 54 24 07 88 4C 24 06 0F B6 44 24 06 0F B6 4C 24 07 31 C8 59 c3}

    condition:
        uint16be(0) == 0x4d5a and all of them and filesize < 4MB
}
