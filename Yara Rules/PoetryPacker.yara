rule PoetryPacker  {
  meta:
      description = "Poetry Packer"
      author = "Alec Dhuse"
      date = "2025-03-25"
      reference = ""
      in_the_wild = true

	strings:
		$re1 = /[a-zA-Z]+\.match\s*\(\/\.\{1,\s*2\}\/g\s*\)[\s\r\n]+\.map\s*\(\s*[a-zA-Z]+\s*\=\>\s*String\.fromCharCode\s*\(parseInt\s*\([a-zA-Z]+\,\s+16\s*\)\)\)[\s\r\n]+\.join\s*\([\'\"]{2}\s*\)\s*\;?/

	condition:
		$re1
}
