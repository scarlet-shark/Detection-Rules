rule G_Backdoor_WAVESHAPER_2 {
	meta:
		author = "Google Threat Intelligence Group (GTIG)"
    description = "Detects UNC1069's WAVESHAPER malware."
    malware = "WAVESHAPER"
    intrusion_set = "UNC1069"
    tags = "UNC1069, WAVESHAPER"
    date = "2025-11-03"
		date_created = "2025-11-03"
		date_modified = "2025-11-03"
		hash = "eb7635f4836c9e0aa4c315b18b051cb5"
		rev = 1
    reference = "https://cloud.google.com/blog/topics/threat-intelligence/unc1069-targets-cryptocurrency-ai-social-engineering"

	strings:
		$str1 = "__Z10RunCommand"
		$str2 = "__Z11GenerateUID"
		$str3 = "__Z11GetResponse"
		$str4 = "__Z13WriteCallback"
		$str5 = "__Z14ProcessRequest"
		$str6 = "__Z14SaveAndExecute"
		$str7 = "__Z16MakeStatusString"
		$str8 = "__Z24GetCurrentExecutablePath"
		$str9 = "__Z7Execute"

	condition:
		all of them
}
