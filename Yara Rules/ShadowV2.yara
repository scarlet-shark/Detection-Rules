rule ShadowV2 {

  meta:
    author = "nathaniel.bill@darktrace.com"
    description = "Detects ShadowV2 botnet implant"
    reference = "https://www.darktrace.com/blog/shadowv2-an-emerging-ddos-for-hire-botnet"
    date = "2025-09-23"
    version = "1.0"
    hash = "2462467c89b4a62619d0b2957b21876dc4871db41b5d5fe230aa7ad107504c99"
    hash = "1b552d19a3083572bc433714dfbc2b75eb6930a644696dedd600f9bd755042f6"
    hash = "1f70c78c018175a3e4fa2b3822f1a3bd48a3b923d1fbdeaa5446960ca8133e9c"

  strings:
    $string1 = "shadow-go"
    $string2 = "shadow.aurozacloud.xyz"
    $string3 = "[SHADOW-NODE]"

    $symbol1 = "main.registerWithMaster"
    $symbol2 = "main.handleStartAttack"
    $symbol3 = "attacker.bypassUAM"
    $symbol4 = "attacker.performHTTP2RapidReset"

    $code1 = { 48 8B 05 ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 89 8C 24 38 01 00 00 48 89 84 24 40 01 00 00 48 8B 4C 24 40 48 BA 00 09 6E 88 F1 FF FF FF 48 8D 04 0A E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 89 8C 24 48 01 00 00 48 89 84 24 50 01 00 00 48 8D 05 ?? ?? ?? ?? BB 05 00 00 00 48 8D 8C 24 38 01 00 00 BF 02 00 00 00 48 89 FE E8 ?? ?? ?? ?? }
    $code2 = { 48 89 35 ?? ?? ?? ?? 0F B6 94 24 80 02 00 00 88 15 ?? ?? ?? ?? 0F B6 94 24 81 02 00 00 88 15 ?? ?? ?? ?? 0F B6 94 24 82 02 00 00 88 15 ?? ?? ?? ?? 0F B6 94 24 83 02 00 00 88 15 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? }
    $code3 = { 48 8D 15 ?? ?? ?? ?? 48 89 94 24 68 04 00 00 48 C7 84 24 78 04 00 00 15 00 00 00 48 8D 15 ?? ?? ?? ?? 48 89 94 24 70 04 00 00 48 8D 15 ?? ?? ?? ?? 48 89 94 24 80 04 00 00 48 8D 35 ?? ?? ?? ?? 48 89 B4 24 88 04 00 00 90 }

  condition:
    uint16(0) == 0x457f and (2 of ($string*) or 2 of ($symbol*) or any of ($code*))
}
