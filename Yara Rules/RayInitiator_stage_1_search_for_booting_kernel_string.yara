rule RayInitiator_stage_1_search_for_booting_kernel_string {
  meta:
    author = "NCSC"
    description = "Detects RayInitiator GRUB bootkit stage 1 code that searches for the 'Booting the kernel' string."
    reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
    date = "2025-09-25"

  strings:
    $ = {BB 00 00 40 00 43 81 FB 00 00 60 00 0F 87 AB 00 00 00 8B 3B 81 FF 64 6F 6E 65 75 E9 83 C3 04 8B 3B 81 FF 2E 0A 42 6F 75 DC 83 C3 04 8B 3B 81 FF 6F 74 69 6E 75 CF 83 C3 04 8B 3B 81 FF 67 20 74 68 75 C2 83 C3 04 8B 3B 81 FF 65 20 6B 65 75 B5 83 C3 04 8B 3B 81 FF 72 6E 65 6C 75 A8 83 EB 14}

  condition:
    any of them
}
