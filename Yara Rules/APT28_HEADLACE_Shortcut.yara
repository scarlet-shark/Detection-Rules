rule APT28_HEADLACE_SHORTCUT {
  meta:
    description = "Detects the HEADLACE backdoor shortcut dropper. Rule is meant for threat hunting."
    author = "Joint Government Cybersecurity Advisory"
    creation_date = "2025-05-21"
    reference = "https://media.defense.gov/2025/May/21/2003719846/-1/-1/0/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.PDF"
    tags = "APT28, HEADLACE"

  strings:
    $type = "[InternetShortcut]" ascii nocase
    $url = "file://"
    $edge = "msedge.exe"
    $icon = "IconFile"

  condition:
    all of them
}
