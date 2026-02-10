rule G_Backdoor_SILENCELIFT_1 {
	meta:
		author = "Google Threat Intelligence Group (GTIG)"
    description = "Detects UNC1069's SILENCELIFT malware."
    malware = "SILENCELIFT"
    intrusion_set = "UNC1069"
    tags = "UNC1069, SILENCELIFT"
		hash = "4e4f2dfe143ba261fd8a18d1c4b58f2e"
    date = "2025-11-23"
		date_created = "2025-11-23"
		date_modified = "2025-11-23"
    hash = "c3e5d878a30a6c46e22d1dd2089b32086c91f13f8b9c413aa84e1dbaa03b9375"
		rev = 2
    reference = "https://cloud.google.com/blog/topics/threat-intelligence/unc1069-targets-cryptocurrency-ai-social-engineering"

	strings:
		$ss1 = "/usr/libexec/PlistBuddy -c \"print :IOConsoleUsers:0:CGSSessionScreenIsLocked\" /dev/stdin 2>/dev/null <<< \"$(ioreg -n Root -d1 -a)\"" ascii fullword
		$ss2 = "pkill -CONT -f" ascii fullword
		$ss3 = "pkill -STOP -f" ascii fullword
		$ss4 = "/Library/Caches/.Logs.db" ascii fullword
		$ss5 = "/Library/Caches/.evt_"
		$ss6 = "{\"bot_id\":\""
		$ss7 = "\", \"status\":"
		$ss8 = "/Library/Fonts/.analyzed" ascii fullword

	condition:
		all of them
}
