rule G_APT_Backdoor_GRIDTIDE_1 {

	meta:
    description = "Detects GRIDTIDE malware."
		author = "Google Threat Intelligence Group (GTIG)"
    reference = "https://cloud.google.com/blog/topics/threat-intelligence/disrupting-gridtide-global-espionage-campaign"
    date = "2026-02-25"
    malware = "GRIDTIDE"
    intrusion_set = "UNC2814"
    tags = "UNC2814, GRIDTIDE"
    hash = "ce36a5fc44cbd7de947130b67be9e732a7b4086fb1df98a5afd724087c973b47"

	strings:
		$s1 = { 7B 22 61 6C 67 22 3A 22 52 53 32 35 36 22 2C 22 6B 69 64 22 3A 22 25 73 22 2C 22 74 79 70 22 3A 22 4A 57 54 22 7D 00 }
		$s2 = { 2F 70 72 6F 63 2F 73 65 6C 66 2F 65 78 65 00 }
		$s3 = { 7B 22 72 61 6E 67 65 73 22 3A 5B 22 61 31 3A 7A 31 30 30 30 22 5D 7D 00 }
		$s4 = { 53 2D 55 2D 25 73 2D 31 00 }
		$s5 = { 53 2D 55 2D 52 2D 31 00 }
		$s6 = { 53 2D 44 2D 25 73 2D 30 00 }
		$s7 = { 53 2D 44 2D 52 2D 25 64 00 }

	condition:
		(uint32(0) == 0x464c457f) and 6 of ($*)
}
