rule PoetryPacker  {
  meta:
      description = "Detection rule for Poetry Packer, a JavaScript code obfuscation tool."
      author = "Alec Dhuse"
      creation_date = "2025-03-25"
      updated_date = "2025-03-27"
      reference = "https://blog.scarletshark.com/analysts-note-phishing-emails-using-svg-images-as-attachments-215cd739204b"
      license = "Detection Rule License (DRL) 1.1"
      license_reference = "https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md"      
      in_the_wild = true
      samples = "bd7b9a246cbf6822a697311203b2dd2d64ca8d25118ded1e4bf7ccceac105f81"
	strings:
		$re1 = /[a-zA-Z]+\.match\s*\(\/\.\{1,\s*2\}\/g\s*\)[\s\r\n]+\.map\s*\(\s*[a-zA-Z]+\s*\=\>\s*String\.fromCharCode\s*\(parseInt\s*\([a-zA-Z]+\,\s+16\s*\)\)\)[\s\r\n]+\.join\s*\([\'\"]{2}\s*\)\s*\;?/

	condition:
		$re1
}
