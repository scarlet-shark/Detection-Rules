rule LINE_VIPER_shellcode_initial_execution {
  meta:
    author = "NCSC"
    description = "Detects LINE VIPER Cisco ASA malware code as part of shellcode initial execution."
    reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/RayInitiator-LINE-VIPER/ncsc-mar-rayinitiator-line-viper.pdf"
    date = "2025-09-25"

  strings:
    $ = {48 8D B7 80 00 00 00 BA 00 20 00 00 [19] 48 C7 C6 00
    90 00 00 BA 07 00 00 00}
    $ = /SI23gAAAALoAIAAA[A-Za-z0-9+\/]{26}jHxgCQAAC6BwAAA/
    $ = /iNt4AAAAC6ACAAA[A-Za-z0-9+\/]{26}Ix8YAkAAAugcAAA/
    $ = /IjbeAAAAAugAgAA[A-Za-z0-9+\/]{26}SMfGAJAAALoHAAAA/

  condition:
    any of them
}
