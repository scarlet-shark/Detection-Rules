import "pe"

rule KugelBlitz : BitterAPT {
    meta:
        author = "Abdallah Elshinbary (n1ghtw0lf), Threatray"
        description = "Detects KugelBlitz shellcode loader used by Bitter APT"
        license = "Detection Rule License (DRL) 1.1"
        license_reference = "https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md"
        creation_date = "2025-06-01"
        date = "2025-06-01"
        reference = "https://www.threatray.com/blog/the-bitter-end-unraveling-eight-years-of-espionage-antics-part-two"
        hash = "a56b5e90a08822483805f9ab38debb028eb5eade8d796ebf0ff1695c3c379618"

    strings:
        $s1 = "run.bin" wide
        $s2 = "Failed to open the file." ascii
        $s3 = "Failed to allocate memory." ascii
        $s4 = "Failed to read the shellcode." ascii
        $s5 = "ShellCode_Loader" ascii

    condition:
        pe.is_pe and
        filesize < 100KB and
        4 of them
}
