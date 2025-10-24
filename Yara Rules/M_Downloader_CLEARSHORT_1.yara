rule M_Downloader_CLEARSHORT_1 {
    meta:
        author = "Mandiant"
        description = "Detects CLEARSHORT malware."
        date = "2025-09-25"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/unc5142-etherhiding-distribute-malware"
        version = "1.0"
        
    strings:
        $payload_b641 = "ipconfig /flushdns" base64
        $payload_b642 = "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(" base64
        $payload_b643 = "[System.Diagnostics.Process]::Start(" base64
        $payload_b644 = "-ep RemoteSigned -w 1 -enc" base64

        $payload_o1 = "ipconfig /flushdns" nocase ascii wide
        $payload_o2 = "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(" nocase ascii wide
        $payload_o3 = "[System.Diagnostics.Process]::Start(" nocase ascii wide
        $payload_o4 = "-ep RemoteSigned -w 1 -enc" nocase ascii wide


        $htm_o1 = "title: \"Google Chrome\","
        $htm_o2 = "PowerShell"
        $htm_o3 = "navigator.clipboard.writeText"
        $htm_o4 = "document.body.removeChild"
        $htm_o5 = "downloadButton.classList.add('downloadButton');"
        $htm_o6 = "getUserLanguage().substring(0, 2);"
        $htm_o7 = "translateContent(userLang);"

        $htm_b64_1 = "title: \"Google Chrome\"," base64
        $htm_b64_2 = "PowerShell" base64
        $htm_b64_3 = "navigator.clipboard.writeText" base64
        $htm_b64_4 = "document.body.removeChild" base64
        $htm_b64_5 = "downloadButton.classList.add('downloadButton');" base64
        $htm_b64_6 = "getUserLanguage().substring(0, 2);" base64
        $htm_b64_7 = "translateContent(userLang);" base64

    condition:
        filesize<1MB and (4 of ($payload_b*) or 4 of ($payload_o*) or 4 of ($htm_b*) or  4 of ($htm_o*))
}
