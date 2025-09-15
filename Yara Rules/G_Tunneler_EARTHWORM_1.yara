rule G_Tunneler_EARTHWORM_1 {
    meta:
        author = "Mandiant"
        description = "Detects the open-source network tunnel tool known as EARTHWORM."
        creation_date = "2025-09-03"
        date = "2025-09-03"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/viewstate-deserialization-zero-day-vulnerability"
        hash = "b3f83721f24f7ee5eb19f24747b7668ff96da7dfd9be947e6e24a688ecc0a52b"

    strings:
    	$s1 = "free1.2"
  		$s2 = ".//xxx ([-options] [values])*"
  		$s3 = "You can create a lcx_listen tunnel like this :"
  		$s4 = ".//ew -s lcx_listen --listenPort 1080 --refPort 8888"
  		$s8 = "I_AM_NEW_RC_CMD_SOCK_CLIENT"
  		$s9 = "CONFIRM_YOU_ARE_SOCK_TUNNEL"
  		$s11 = "lcx_listen" fullword
  		$s12 = "call back cmd_socks ok"
  		$s13 = "lcx_tran" fullword
  		$s14 = "lcx_slave" fullword
  		$s15 = "rssocks" fullword
  		$s16 = "ssocksd" fullword
  		$s17 = "rcsocksd" fullword
		  $marker1= "earthworm" nocase ascii wide
		  $marker2 = "rootkiter" nocase ascii wide

	condition:
		((uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550) or uint32(0) == 0x464c457f or (uint32(0) == 0xBEBAFECA or uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF or uint32(0) == 0xCEFAEDFE)) and
		(4 of ($s*) or all of ($marker*))
}
