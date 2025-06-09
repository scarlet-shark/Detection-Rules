rule ORPCBackdoor : BitterAPT {
    meta:
        author = "Abdallah Elshinbary (n1ghtw0lf), Threatray"
        description = "Detects ORPCBackdoor used by Bitter APT"
        license = "Detection Rule License (DRL) 1.1"
        license_reference = "https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md"
        creation_date = "2025-06-01"        
        date = "2025-06-01"
        reference = "https://www.threatray.com/blog/the-bitter-end-unraveling-eight-years-of-espionage-antics-part-two"
        hash = "8aeb7dd31c764b0cf08b38030a73ac1d22b29522fbcf512e0d24544b3d01d8b3"
        hash = "dd53768eb7d5724adeb58796f986ded3c9b469157a1a1757d80ccd7956a3dbda"

    strings:
        $rpc = "RPCRT4.dll"

        $s1  = "Host Name:\t\t\t" ascii
        $s2  = "OS Build Type :\t\t\t" ascii
        $s3  = "Registered Owner:\t\t" ascii
        $s4  = "Product ID:\t\t\t" ascii
        $s5  = "Install Date:\t\t\t" ascii
        $s6  = "System Manufacturer:\t\t" ascii
        $s7  = "Processor(s):\t\t\t" ascii
        $s8  = "BiosVersion:\t\t\t" ascii
        $s9  = "BIOSVENDOR:\t\t\t" ascii
        $s10 = "BIOS Date:\t\t\t" ascii
        $s11 = "Boot Device:\t\t\t" ascii
        $s12 = "Input Locale:\t\t\t" ascii
        $s13 = "Time zone:\t\t\t" ascii
        $s14 = "Total Physical Memory:\t\t" ascii
        $s15 = "Virtual Memory: In Use:\t\t" ascii
        $s16 = "Page File Location(s):\t\t" ascii
        $s17 = "Error! GetComputerName failed.\n" ascii
        $s18 = "Error! RegOpenKeyEx failed.\n" ascii
        $s19 = "IA64-based PC" wide
        $s20 = "AMD64-based PC" wide
        $s21 = "X86-based PC" wide
        $s22 = "%s\\oeminfo.ini" wide

    condition:
        pe.is_pe and
        $rpc and 15 of ($s*)
}
