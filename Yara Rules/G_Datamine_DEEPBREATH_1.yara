rule G_Datamine_DEEPBREATH_1 {
	meta:
		author = "Google Threat Intelligence Group (GTIG)"
    description = "Detects UNC1069's DEEPBREATH malware."
    malware = "DEEPBREATH"
    intrusion_set = "UNC1069"
    tags = "UNC1069, DEEPBREATH"
    date = "2025-11-06"
    hash = "b452C2da7c012eda25a1403b3313444b5eb7C2c3e25eee489f1bd256f8434735"
    reference = "https://cloud.google.com/blog/topics/threat-intelligence/unc1069-targets-cryptocurrency-ai-social-engineering"

	strings:
		$sa1 = "-fakedel"
		$sa2 = "-autodat"
		$sa3 = "-datadel"
		$sa4 = "-extdata"
		$sa5 = "TccClickJack"
		$sb1 = "com.apple.TCC\" as alias"
		$sb2 = "/TCC.db\" as alias"
		$sc1 = "/group.com.apple.notes\") as alias"
		$sc2 = ".keepcoder.Telegram\")"
		$sc3 = "Support/Google/Chrome/\")"
		$sc4 = "Support/BraveSoftware/Brave-Browser/\")"
		$sc5 = "Support/Microsoft Edge/\")"
		$sc6 = "& \"/Local Extension Settings\""
		$sc7 = "& \"/Cookies\""
		$sc8 = "& \"/Login Data\""
		$sd1 = "\"cp -rf \" & quoted form of "

	condition:
		(uint32(0) == 0xfeedfacf) and 2 of ($sa*) and 2 of ($sb*) and 3 of ($sc*) and 1 of ($sd*)
}
