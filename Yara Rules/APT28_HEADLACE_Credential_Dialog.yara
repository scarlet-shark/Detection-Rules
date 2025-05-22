rule APT28_HEADLACE_CREDENTIALDIALOG {
  meta:
    description = "Detects scripts used by APT28 to lure user into entering credentials"
    author = "Joint Government Cybersecurity Advisory"
    creation_date = "2025-05-21"
    reference = "https://media.defense.gov/2025/May/21/2003719846/-1/-1/0/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.PDF"
    tags = "APT28, HEADLACE"
    
  strings:
    $command_1 = "while($true)"
    $command_2 = "Get-Credential $(whoami)"
    $command_3 = "Add-Content"
    $command_4 = ".UserName"
    $command_5 = ".GetNetworkCredential().Password"
    $command_6 = "GetNetworkCredential().Password.Length -ne 0"

  condition:
    5 of them
}
