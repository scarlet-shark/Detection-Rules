rule G_APT_BackdoorWebshell_SLAYSTYLE_4 {

	meta:
    description = "Detects SLAYSTYLE Backdoor Webshell."
    malware = "SLAYSTYLE"
    intrusion_set = "UNC6201"
    tags = "UNC6201, SLAYSTYLE"    
		author = "Google Threat Intelligence Group (GTIG)"
    reference = "https://cloud.google.com/blog/topics/threat-intelligence/unc6201-exploiting-dell-recoverpoint-zero-day"
    date = "2026-02-17"
    hash = "92fb4ad6dee9362d0596fda7bbcfe1ba353f812ea801d1870e37bfc6376e624a"

	strings:
		$str1 = "<%@page import=\"java.io" ascii wide
		$str2 = "Base64.getDecoder().decode(c.substring(1)" ascii wide
		$str3 = "{\"/bin/sh\",\"-c\"" ascii wide
		$str4 = "Runtime.getRuntime().exec(" ascii wide
		$str5 = "ByteArrayOutputStream();" ascii wide
		$str6 = ".printStackTrace(" ascii wide

	condition:
		$str1 at 0 and all of them
}
