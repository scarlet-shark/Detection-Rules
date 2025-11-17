import "pe"

rule M_APT_Utility_DCSYNCER_SLICK_1 {
	meta:
    description = "Detects DCSYNCER.SLICK malware."
		author = "Google Threat Intelligence Group (GTIG)"
    date = "2025-11-17"
    reference = "https://cloud.google.com/blog/topics/threat-intelligence/analysis-of-unc1549-ttps-targeting-aerospace-defense"
		hash = "10f16991665df69d1ccd5187e027cf3d"
    malware = "DCSYNCER.SLICK"
    intrusion_set = "UNC1549"
    tags = "DCSYNCER.SLICK, UNC1549"

	strings:
		$ = { 48 89 84 24 ?? 01 00 00 C7 84 24 ?? 01 00 00 30 80 28 00 C7 84 24 ?? 01 00 00 E8 03 00 00 48 C7 84 24 ?? 01 00 00 00 00 A0 00 BA ?? 00 00 00 8D 4A ?? FF 15 ?? ?? 01 00 48 89 84 24 ?? 01 00 00 C7 00 01 00 00 00 48 8B 84 24 ?? 01 00 00 44 89 ?? 04 48 8B 84 24 ?? 01 00 00 C7 40 08 ?? 00 00 00 41 8B ?? }
		$ = "\\LOG.txt" ascii wide
		$ = "%ws_%d:%d:" ascii wide fullword
		$ = "%ws:%d:" ascii wide fullword
		$ = "::::" ascii wide fullword
		$ = "%ws_%d:%d::" ascii wide fullword
		$ = "%ws:%d::" ascii wide fullword

	condition:
		pe.is_pe and all of them
}
