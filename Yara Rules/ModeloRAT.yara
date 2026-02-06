rule ModeloRAT {
    meta:
        author = "RussianPanda"
        description = "Detects ModeloRAT Python RAT used by KongTuke"
        date = "2026-01-16"
        hash = "c15f44d6abb3a2a882ffdc9b90f7bb5d1a233c0aa183eb765aa8bfba5832c8c6"
        reference = "https://github.com/RussianPanda95/Yara-Rules/blob/main/KongTuke/ModeloRAT.yar"

    strings:
        $s1 = "UnnecessarilyProlongedCryptographicMechanismImplementationClass"
        $s2 = "_enumerate_executing_processes"
        $s3 = "_enumerate_network_connections"

    condition:
        all of them
}
