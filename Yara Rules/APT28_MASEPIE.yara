rule APT28_MASEPIE {
  meta:
    description = "Detects MASEPIE python script"
    author = "Joint Government Cybersecurity Advisory"
    creation_date = "2025-05-21"
    reference = "https://media.defense.gov/2025/May/21/2003719846/-1/-1/0/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.PDF"
    tags = "APT28, MASEPIE"  

  strings:
    $masepie_unique_1 = "os.popen('whoami').read()"
    $masepie_unique_2 = "elif message == 'check'"
    $masepie_unique_3 = "elif message == 'send_file':"
    $masepie_unique_4 = "elif message == 'get_file'"
    $masepie_unique_5 = "enc_mes('ok'"
    $masepie_unique_6 = "Bad command!'.encode('ascii'"
    $masepie_unique_7 = "{user}{SEPARATOR}{k}"
    $masepie_unique_8 = "raise Exception(\"Reconnect"

  condition:
    3 of ($masepie_unique_*)
}
