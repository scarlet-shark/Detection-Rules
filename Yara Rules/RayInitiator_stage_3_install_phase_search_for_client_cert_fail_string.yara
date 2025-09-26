rule RayInitiator_stage_3_install_phase_search_for_client_cert_fail_string {
  meta:
    author = "NCSC"
    description = "Detects RayInitiator GRUB bootkit stage 3 install phase code that searches for the 'client-cert-fail' string."
    reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
    date = "2025-09-25"

  strings:
    $ = {48 81 EE 00 00 00 08 48 B8 63 6C 69 65 6E 74 2D 63 49 B8 65 72 74 2D 66 61 69 6C 48 FF C6 48 39 D6 0F 87 D2 00 00 00 48 8B 3E 48 39 C7}

  condition:
    any of them
}
