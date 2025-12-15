rule G_Hunting_Downloader_SNOWLIGHT_1 {

	meta:
    description = "Detects SNOWLIGHT malware."
		author = "Google Threat Intelligence Group (GTIG)"
    date = "2025-03-25"
		date_created = "2025-03-25"
		date_modified = "2025-03-25"
    hash = "3a7b89429f768fdd799ca40052205dd4"
		md5 = "3a7b89429f768fdd799ca40052205dd4"
		rev = 1
    reference = "https://cloud.google.com/blog/topics/threat-intelligence/threat-actors-exploit-react2shell-cve-2025-55182"
    malware = "SNOWLIGHT"

	strings:
		$str1 = "rm -rf $v"
		$str2 = "&t=tcp&a="
		$str3 = "&stage=true"
		$str4 = "export PATH=$PATH:$(pwd)"
		$str5 = "curl"
		$str6 = "wget"
		$str7 = "python -c 'import urllib"

	condition:
		all of them and filesize < 5KB
}
