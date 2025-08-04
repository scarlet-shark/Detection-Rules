rule Kimsuky_Lure_PDF  {
  meta:
      description = "Detection rule for a PDF file created by Kimsuky / APT43"
      author = "Alec Dhuse"
      creation_date = "2025-07-28"
      updated_date = "2025-07-28"
      date = "2025-07-28"
      in_the_wild = true
      threat_actor = "Kimsuky"
      hash = "ddf2832cde87548132688b28a27e6b4a0103e7d07fb88a5f10225145daa88926"
      rule_version = "1.0"
      license = "Detection Rule License (DRL) 1.1"
      license_reference = "https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md"      
	strings:
		$re1 = /<<\s*\/Author\s*\(Raizo\)\s*\/Creator\s*\(þÿ\x00?M\x00?i\x00?c\x00?r\x00?o\x00?s\x00?o\x00?f\x00?t\x00?®\x00?\s+\x00?W\x00?o\x00?r\x00?d\x00?\s+\x00?2\x00?0\x00?1\x00?3\s*\)/

	condition:
		$re1
}
