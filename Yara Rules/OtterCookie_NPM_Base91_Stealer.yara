rule OtterCookie_NPM_Base91_Stealer {
    meta:
        description = "Detects OtterCookie npm stealer with custom base91 encoding"
        author = "PantherLabs"
        date = "2026-04-09"
        reference = "https://panther.com/blog/tracking-an-ottercookie-infostealer-campaign-across-npm"

    strings:
        $const_array = /const\s+\w+\s*=\s*\[0x0,\s*0x1,\s*0x8,\s*0xff,\s*"length",\s*"undefined",\s*0x3f/
        $from_code_point = "\"fromCodePoint\"" ascii
        $push_method = "\"push\"" ascii
        $base91_magic1 = "0x5b" ascii
        $base91_magic2 = "0x1fff" ascii
        $base91_magic3 = "0x58" ascii
        $utf8_decoder = "fromCharCode" ascii
        $alphabet_pattern = /var\s+\w+\s*=\s*"[^\\"]{85,95}"/

    condition:
        filesize < 200KB and
        $const_array and
        $from_code_point and
        $push_method and
        all of ($base91_magic*) and
        $utf8_decoder and
        #alphabet_pattern > 3
}

rule OtterCookie_NPM_Loader {
    meta:
        description = "Detects OtterCookie npm loader component"
        author = "PantherLabs"
        date = "2026-04-09"

    strings:
        $const_array = /const\s+\w+\s*=\s*\[0x0,\s*0x1,\s*0x8,\s*0xff,\s*"length",\s*"undefined"/
        $require_dot = "require(\".\")" ascii
        $async_try = /async\s+function\s+\w+\(\)\s*\{\s*try\s*\{\s*await\s+\w+\(\)/
        $silent_catch = /catch\s*\(\s*\w*\s*\)\s*\{\s*\}/

    condition:
        filesize < 50KB and
        $const_array and
        $require_dot and
        $async_try and
        $silent_catch
}
