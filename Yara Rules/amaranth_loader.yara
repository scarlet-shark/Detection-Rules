rule amaranth_loader {
  meta:
    author = "@Tera0017/@_CPResearch_"
    description = "Amaranth Loader"
    reference = "https://research.checkpoint.com/2026/amaranth-dragon-weaponizes-cve-2025-8088-for-targeted-espionage/"
    hash = "d7711333c34a27aed5d38755f30d14591c147680e2b05eaa0484c958ddaae3b6"
    malware = "Amaranth Loader"
    intrusion_set = "APT41"
    tags = "APT41, Amaranth Loader"
    date = "2026-02-04"

  strings:
    $mz = "MZ"
    $ama_size = {41 BD 01 00 00 00 41 BC 00 40 06 00 E9 92 00 00 00}
    $ama_iv = {C7 84 24 30 02 00 00 12 34 56 78 C7 84 24 34 02 00 00 90 AB CD EF C7 84 24 38 02 00 00 34 56 78 90 C7 84 24 3C 02 00 00 AB CD EF 12}
    $ama_decr = {FF C1 48 D3 E8 41 30 00 FF C2 49 FF C0}

  condition:
    $mz at 0 and any of ($ama*)
}
