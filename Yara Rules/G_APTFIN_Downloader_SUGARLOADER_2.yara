rule G_APTFIN_Downloader_SUGARLOADER_2 {
	meta:
		author = "Google Threat Intelligence Group (GTIG)"
    description = "Detects UNC1069's SUGARLOADER malware."
    malware = "SUGARLOADER"
    intrusion_set = "UNC1069"
    tags = "UNC1069, SUGARLOADER"
    date = "2025-11-06"
    hash = "1a30d6cdb0b98feed62563be8050db55ae0156ed437701d36a7b46aabf086ede"
    reference = "https://cloud.google.com/blog/topics/threat-intelligence/unc1069-targets-cryptocurrency-ai-social-engineering"

	strings:
		$m1 = "__mod_init_func\x00lko2\x00"
		$m2 = "__mod_term_func\x00lko2\x00"
		$m3 = "/usr/lib/libcurl.4.dylib"

	condition:
		(uint32(0) == 0xfeedface or uint32(0) == 0xfeedfacf or uint32(0) == 0xcefaedfe or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe) and (all of ($m1, $m2, $m3))
}
