rule FIREANT_BridgeAgent_Systemd_Unit {
    meta:
        description = "Detects the companion systemd service from the analyzed sample"
        author = "Sygnia analysis"
        date = "2026-08-27"
        sha256 = "251c7a2684542c29ae2c1e1282b780163bf9f844179ef0759094b2b7e2f62f0f"
        hash = "251c7a2684542c29ae2c1e1282b780163bf9f844179ef0759094b2b7e2f62f0f"
        reference = "https://www.sygnia.co/blog/fire-ant-evolves-from-hypervisors-to-trusted-infrastructure/"

    strings:
        $a = "Description=Service for zabbix hosted on PVE" ascii
        $b = "Type=forking" ascii
        $c = "ExecStart=/usr/sbin/zabbix_agent 60" ascii
        $d = "Restart=always" ascii
        $e = "User=root" ascii

    condition:
        all of them
}
