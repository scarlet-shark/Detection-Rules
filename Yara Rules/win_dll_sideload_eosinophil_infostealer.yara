import "pe"

rule win_dll_sideload_eosinophil_infostealer {

  meta:
    author = "VirusTotal"
    description = "Detects malicious DLLs (CoreMessaging.dll) from an infostealer campaign impersonating Malwarebytes, Logitech, and others via DLL sideloading."
    reference = "https://blog.virustotal.com/2026/01/malicious-infostealer-january-26.html"
    date = "2026-01-16"
    behash = "4acaac53c8340a8c236c91e68244e6cb"
    target_entity = "file"
    hash = "606baa263e87d32a64a9b191fc7e96ca066708b2f003bde35391908d3311a463"

  condition:
    (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and pe.is_dll()) and
    pe.exports("15Mmm95ml1RbfjH1VUyelYFCf") and pe.exports("2dlSKEtPzvo1mHDN4FYgv")
}
