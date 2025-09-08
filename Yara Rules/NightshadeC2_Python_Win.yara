rule NightshadeC2_Python_Win {
    meta:
        author = "YungBinary"
        description = "Detects PyNightshade on disk"
        creation_date = "2025-09-04"
        date = "2025-09-04"
        in_the_wild = true
        reference = "https://www.esentire.com/blog/new-botnet-emerges-from-the-shadows-nightshadec2"
        tags = "NightshadeC2"
        version = "1.0"
        hash = "85b4d29f2830a3be3a0f51fbe358bea1a35d2a8aaa6a24f5cc1f2e5d2769716e"

    strings:
        $s1 = "Winhttp.WinHttpOpenRequest(hConnect, \"GET\", \"line/?fields=" ascii
        $s2 = "MachineGuid" ascii
        $s3 = "i = (i + 1) % 256" ascii

    condition:
        all of them
}
