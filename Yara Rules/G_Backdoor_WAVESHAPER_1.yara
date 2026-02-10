rule G_Backdoor_WAVESHAPER_1 {
	meta:
		author = "Google Threat Intelligence Group (GTIG)"
    description = "Detects UNC1069's WAVESHAPER malware."
    malware = "WAVESHAPER"
    intrusion_set = "UNC1069"
    tags = "UNC1069, WAVESHAPER"
    date = "2025-11-03"
		date_created = "2025-11-03"
		date_modified = "2025-11-03"
		hash = "c91725905b273e81e9cc6983a11c8d60"
		rev = 1
    reference = "https://cloud.google.com/blog/topics/threat-intelligence/unc1069-targets-cryptocurrency-ai-social-engineering"

	strings:
		$str1 = "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)"
		$str2 = "/tmp/.%s"
		$str3 = "grep \"Install Succeeded\" /var/log/install.log | awk '{print $1, $2}'"
		$str4 = "sysctl -n hw.model"
		$str5 = "sysctl -n machdep.cpu.brand_string"
		$str6 = "sw_vers --ProductVersion"

	condition:
		all of them
}
