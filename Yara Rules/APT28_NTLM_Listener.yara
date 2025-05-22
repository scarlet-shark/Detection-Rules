rule APT28_NTLM_LISTENER {
  meta:
    description = "Detects NTLM listeners including APT28's custom one"
    author = "Joint Government Cybersecurity Advisory"
    creation_date = "2025-05-21"
    reference = "https://media.defense.gov/2025/May/21/2003719846/-1/-1/0/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.PDF"
    tags = "APT28"

  strings:
    $command_1 = "start-process powershell.exe -WindowStyle hidden"
    $command_2 = "New-Object System.Net.HttpListener"
    $command_3 = "Prefixes.Add('http://localhost:8080/')"
    $command_4 = "-match 'Authorization'"
    $command_5 = "GetValues('Authorization')"
    $command_6 = "Request.RemoteEndPoint.Address.IPAddressToString"
    $command_7 = "@(0x4e,0x54,0x4c,0x4d,
    0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x28,0x00,0x00,0x01,0x82,0x00
    ,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)"
    $command_8 = ".AllKeys"
    $variable_1 = "$NTLMAuthentication" nocase
    $variable_2 = "$NTLMType2" nocase
    $variable_3 = "$listener" nocase
    $variable_4 = "$hostip" nocase
    $variable_5 = "$request" nocase
    $variable_6 = "$ntlmt2" nocase
    $variable_7 = "$NTLMType2Response" nocase
    $variable_8 = "$buffer" nocase

  condition:
    5 of ($command_*)
    or
    all of ($variable_*)
}
