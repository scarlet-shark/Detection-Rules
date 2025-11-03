import "pe"

rule targeted_UNC6384_CanonStager_Loader: extended description {
    meta:
        description = "Detects CanonStager DLL loader used for side-loading PlugX payload"
        author = "Arctic Wolf Labs"
        reference = "https://arcticwolf.com/resources/blog/unc6384-weaponizes-zdi-can-25373-vulnerability-to-deploy-plugx/"
        distribution = "TLP:GREEN"
        version = "1.0"
        date = "2025-10-12"
        last_modified = "2025-10-12"
        hash = "e53bc08e60af1a1672a18b242f714486ead62164dda66f32c64ddc11ffe3f0df"

    strings:
        $str1 = ".dat" wide
        $str2 = "\\cnmplog" wide

        // RC4 decryption loop patterns
        $code1 = {43 0F B6 ?? 0F B6 [3]00 D0 0F B6 ?? 8A 74 [2]88 74 [2]88 54 [2]8B 7? [2]02 54 [2]0F B6 ?? 0F B6 [3]32 14 ?? [0-4] 88 14 ?? 41 39 ?? 75 C?}
        $code2 = {0F B6 [3] 89 ?? 83 E? 0F 00 D0 02 ?? [1-2] 0F B6 ?? 8A 74 [2] 88 74 [2] 4? 88 54 [2]81 F? 00 01 00 00 75 D?}
        $code3 = {40 89 ?? 0F B6 C0 0F B6 [3]00 D9 88 9? [4-5]0F B6 F? 8A 7C 3? ?? 88 7C 0? ?? 88 5C 3? ?? 02 5C 0? ?? 0F B6 F? 0F B6 5C 3? ??}

    condition:
        uint16(0) == 0x5a4d and
        all of ($str*) and
        2 of ($code*)
}
