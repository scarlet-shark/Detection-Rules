rule G_Backdoor_WAVESHAPER_V2_PS_1 {
    meta:
        description = "Detects the WAVESHAPER.V2 PowerShell backdoor which communicates with C2 via base64 encoded JSON beacons and supports PE injection and script execution"
        author = "GTIG"
        hash = "04e3073b3cd5c5bfcde6f575ecf6e8c1"
        date_created = "2026-03-31"
        date_modified = "2026-03-31"
        date = "2026-03-31"
        rev = 1
        platforms = "Windows"
        family = "WAVESHAPER"
        intrusion_set = "UNC10691"
        tags = "UNC1069, WAVESHAPER"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package"


    strings:
        $ss1 = "packages.npm.org/product1" ascii wide nocase
        $ss2 = "Extension.SubRoutine" ascii wide nocase
        $ss3 = "rsp_peinject" ascii wide nocase
        $ss4 = "rsp_runscript" ascii wide nocase
        $ss5 = "rsp_rundir" ascii wide nocase
        $ss6 = "Init-Dir-Info" ascii wide nocase
        $ss7 = "Do-Action-Ijt" ascii wide nocase
        $ss8 = "Do-Action-Scpt" ascii wide nocase

    condition:
        uint16(0) != 0x5A4D and filesize < 100KB and 5 of ($ss*)
}
