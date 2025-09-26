rule RayInitiator_stage_2_identify_syscall_table {
  meta:
    author = "NCSC"
    description = "Detects RayInitiator GRUB bootkit stage 2 code that identifies the Linux kernel syscall table."
    reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
    date = "2025-09-25"

  strings:
    $ = {49 89 E0 48 83 F8 30 0F 84 70 00 00 00 49 01 C0 49 8B 10 48 83 C0 08 66 85 D2 75 E4 BF ?? ?? 60 00 48 8B 3C 17 48 BE 6E 6D 69 5F 6D 61 78 5F}

  condition:
    any of them
}
