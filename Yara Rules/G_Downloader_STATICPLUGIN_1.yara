rule G_Downloader_STATICPLUGIN_1 {
    meta:
        description = "STATICPLUGIN is a downloader observed to retrieve an MSI packaged payload from a hard-coded C2 domain."
        author = "GTIG"
        date = "2025-07-24"
        date_created = "2025-07-24"
        date_modified = "2025-07-24"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/prc-nexus-espionage-targets-diplomats/"
        in_the_wild = true
        tags = "UNC6384"
        hash = "52f42a40d24e1d62d1ed29b28778fc45"
        rev = 1
        version = "1.0"

    strings:
        $s1 = "InstallRemoteMSI"
        $s2 = "InstallUpdate"
        $s3 = "Button1Click"
        $s4 = "Button2Click"
        $s5 = "WindowsInstaller.Installer" wide

    condition:
        uint16(0)==0x5a4d and all of them
}
