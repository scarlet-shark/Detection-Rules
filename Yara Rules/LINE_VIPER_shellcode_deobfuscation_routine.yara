rule LINE_VIPER_shellcode_deobfuscation_routine {
  meta:
    author = "NCSC"
    description = "Detects LINE VIPER Cisco ASA malware code as part of a shellcode deobfuscation routine."
    reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
    date = "2025-09-25"

  strings:
    $ = {48 8B 7F 08 48 8D 5F 70 49 C7 C1 00 18 00 00 49 C7 C0
    20 00 00 00 48 89 DF 8A 01 32 07 48 FF C7 41 FF C8 4D 85 C0 75 F3
    88 01 48 FF C1 41 FF C9 4D 85 C9 75 DA}
    $ = "SIt/CEiNX3BJx8EAGAAAScfAIAAAAEiJ34oBMgdI/8dB/8hNhcB184gBSP/BQf/JTYXJdd"
    $ = "iLfwhIjV9wScfBABgAAEnHwCAAAABIid+KATIHSP/HQf/ITYXAdfOIAUj/wUH/yU2FyXXa"
    $ = "Ii38ISI1fcEnHwQAYAABJx8AgAAAASInfigEyB0j/x0H/yE2FwHXziAFI/8FB/8lNhcl12"

  condition:
    any of them
}
