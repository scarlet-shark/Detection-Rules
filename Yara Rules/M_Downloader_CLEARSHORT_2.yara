rule M_Downloader_CLEARSHORT_2 {
    meta:
          author = "Mandiant"
          description = "Detects CLEARSHORT malware."
          date = "2025-10-16"
          reference = "https://cloud.google.com/blog/topics/threat-intelligence/unc5142-etherhiding-distribute-malware"
          version = "1.0"
                    
    strings:
        $htm1 = "const base64HtmlContent"
        $htm2 = "return decodeURIComponent(escape(atob(str)));"
        $htm3 = "document.body.style.overflow = 'hidden';"
        $htm4 = "document.body.append(popupContainer);"
        $htm5 = "Object.assign(el.style, styles);"


        $htm_b64_1 = "const base64HtmlContent" base64
        $htm_b64_2 = "return decodeURIComponent(escape(atob(str)));" base64
        $htm_b64_3 = "document.body.style.overflow = 'hidden';" base64
        $htm_b64_4 = "document.body.append(popupContainer);" base64
        $htm_b64_5 = "Object.assign(el.style, styles);" base64

    condition:
        filesize<1MB and 5 of ($htm*)
}
