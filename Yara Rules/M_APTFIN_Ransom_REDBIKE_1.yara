rule M_APTFIN_Ransom_REDBIKE_1 {
	meta:
  description = "Detects REDBIKE / Akira ransomware."
  creation_date = "2026-03-17"
  reference = "https://cloud.google.com/blog/topics/threat-intelligence/ransomware-ttps-shifting-threat-landscape/"
  author = "Google Threat Intelligence Group (GTIG)"

	strings:
		$a = "akira_readme.txt"
		$b = "save your TIME, MONEY, EFFORTS"
		$c = "akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion"
		$d = "--encryption_percent"
		$e = "--encryption_path"
		$f = "--share_file"
	condition:
		all of them and (uint32be(0) == 0x7F454C46)
}
