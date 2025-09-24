rule G_APT_Backdoor_BRICKSTORM_3 {

	meta:
		author = "Google Threat Intelligence Group (GTIG)"
    date = "2025-09-24"
    date_created = "2025-09-24"
    date_modified = "2025-09-24"
    reference = "https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign"
    version = "1.0"
    
strings:
		$str1 = { 48 8B 05 ?? ?? ?? ?? 48 89 04 24 E8 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 04 24 [0-5] E8 ?? ?? ?? ?? EB ?? }
		$str2 = "regex" ascii wide nocase
		$str3 = "mime" ascii wide nocase
		$str4 = "decompress" ascii wide nocase
		$str5 = "MIMEHeader" ascii wide nocase
		$str6 = "ResolveReference" ascii wide nocase
		$str7 = "115792089210356248762697446949407573529996955224135760342422259061068512044369115792089210356248762697446949407573530086143415290314195533631308867097853951" ascii wide nocase

	condition:
		uint16(0) == 0x457F and all of them
}
