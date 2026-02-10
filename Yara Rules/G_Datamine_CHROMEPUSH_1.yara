rule G_Datamine_CHROMEPUSH_1 {
	meta:
		author = "Google Threat Intelligence Group (GTIG)"
    description = "Detects UNC1069's CHROMEPUSH malware."
    malware = "CHROMEPUSH"
    intrusion_set = "UNC1069"
    tags = "UNC1069, CHROMEPUSH"
    date = "2025-11-06"
		date_created = "2025-11-06"
		date_modified = "2025-11-06"
		rev = 1
    hash = "603848f37ab932dccef98ee27e3c5af9221d3b6ccfe457ccf93cb572495ac325"
    reference = "https://cloud.google.com/blog/topics/threat-intelligence/unc1069-targets-cryptocurrency-ai-social-engineering"

	strings:
		$s1 = "%s/CA%02d%02d%02d%02d%02d%02d.dat"
		$s2 = "%s/tmpCA.dat"
		$s3 = "mouseStates"
		$s4 = "touch /Library/Caches/.evt_"
		$s5 = "cp -f"
		$s6 = "rm -rf"
		$s7 = "keylogs"
		$s8 = "%s/KL%02d%02d%02d%02d%02d%02d.dat"
		$s9 = "%s/tmpKL.dat"
		$s10 = "OK: Create data.js success"

	condition:
		(uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca or uint32(0) == 0xcafebabf or uint32(0) == 0xbfbafeca) and 8 of them
}
