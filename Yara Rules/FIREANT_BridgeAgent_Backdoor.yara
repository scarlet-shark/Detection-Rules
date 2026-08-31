rule FIREANT_BridgeAgent_Backdoor {
    meta:
        description = "Detects Fire Ant BridgeAgent Linux backdoor"
        author = "Sygnia"
        date = "2026-08-27"
        sha256 = "110e6fb23be00d2ed251a445ee5b65aadf23b48b8db7419900d64539ad90c5a3"
        hash = "110e6fb23be00d2ed251a445ee5b65aadf23b48b8db7419900d64539ad90c5a3"
        reference = "https://www.sygnia.co/blog/fire-ant-evolves-from-hypervisors-to-trusted-infrastructure/"

    strings:
        $s1 = "[+] ########## GetRemoteCfg ##########" ascii
        $s2 = "[+] ########## ParseJson ##########" ascii
        $s3 = "[+] reverse_shell..." ascii
        $s4 = "If you want me to fake your argv, you need to call the program with a longer name." ascii
        $s5 = "/message/" ascii
        $s6 = "thread: running timeout" ascii
        $s7 = "fMDJLBukHuXgtFsCW68o5Zs1qGf" ascii
        $s8 = "2y7b4BSVukszyZz2vuZMppaA4" ascii
        $aes_key = { 07 FA AA 79 67 F1 3F 26 22 8F 5E 9A C9 0B F1 54 }

    condition:
        uint32(0) == 0x464C457F and
        5 of ($s*) and
        $aes_key
}
