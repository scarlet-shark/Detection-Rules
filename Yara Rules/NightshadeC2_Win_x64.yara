rule NightshadeC2_Win_x64 {
    meta:
        author = "YungBinary"
        description = "Detects NightshadeC2 in memory"
        creation_date = "2025-09-04"
        date = "2025-09-04"
        in_the_wild = true
        reference = "https://www.esentire.com/blog/new-botnet-emerges-from-the-shadows-nightshadec2"
        tags = "NightshadeC2"
        version = "1.0"
        hash = "5a741df3e4a61b8632f62109a65afc0f297f4ed03cd7e208ffd2ea5e2badf318"

    strings:
        $a = "camera!" wide
        $b = "keylog.txt" wide
        $c = "powershell Start-Sleep -Seconds 3; Remove-Item -Path %ws -Force" wide
        $d = "MachineGuid" wide
        $e = "[%02d:%02d %02d.%02d.%02d] %ws"

    condition:
        4 of them
}
