rule G_APTFIN_Downloader_SUGARLOADER_1 {
	meta:
		author = "Google Threat Intelligence Group (GTIG)"
    description = "Detects UNC1069's SUGARLOADER malware."
    malware = "SUGARLOADER"
    intrusion_set = "UNC1069"
    tags = "UNC1069, SUGARLOADER"
		hash = "3712793d3847dd0962361aa528fa124c"
    date = "2025-11-15"
		date_created = "2025-11-15"
		date_modified = "2025-11-15"
		rev = 1
    reference = "https://cloud.google.com/blog/topics/threat-intelligence/unc1069-targets-cryptocurrency-ai-social-engineering"

	strings:
		$ss1 = "/Library/OSRecovery/com.apple.os.config"
		$ss2 = "/Library/Group Containers/OSRecovery"
		$ss4 = "_wolfssl_make_rng"

	condition:
		all of them
}
