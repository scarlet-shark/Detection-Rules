rule M_Ransom_REDBIKE_2 {
	meta:
    creation_date = "2026-03-17"
    reference = "https://cloud.google.com/blog/topics/threat-intelligence/ransomware-ttps-shifting-threat-landscape/"
		author = "Google Threat Intelligence Group (GTIG)"

	strings:
		$a1 = ".akira"
		$a2 = "akira_readme.txt"
		$a3 = "akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4csgfameg52n7efvr2id"
		$s1 = "--encryption_percent" ascii wide nocase
		$s2 = "--encryption_path" ascii wide nocase
		$s3 = "--share_file" ascii wide nocase
	condition:
		((all of ($s*)) and (any of ($a*))) and (uint16(0) == 0x5A4D) and filesize > 500KB and filesize < 2MB
}
