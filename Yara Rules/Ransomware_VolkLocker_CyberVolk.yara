rule Ransomware_VolkLocker_CyberVolk {
    meta:
        description = "Detects VolkLocker (CyberVolk) ransomware based on plaintext key artifact and UAC bypass strings"
        author = "Scarlet Shark"
        reference = "https://www.sentinelone.com/blog/cybervolk-returns-flawed-volklocker-brings-new-features-with-growing-pains/"
        date = "2025-12-15"
        malware = "VolkLocker"
        intrusion_set = "CyberVolk"
        tags = "CyberVolk, VolkLocker"        
        hash = "0948e75c94046f0893844e3b891556ea48188608"
        hash= "dcd859e5b14657b733dfb0c22272b82623466321"

    strings:
        // CRITICAL INDICATOR: The plaintext key file flaw
        // The malware hardcodes this filename to write the master key to %TEMP%
        $key_file = "system_backup.key" ascii wide

        // The format used inside the backup key file (User ID prefix)
        $key_format = "User: CV" ascii

        // Known extensions used by VolkLocker
        $ext1 = ".cvolk" ascii wide
        $ext2 = ".locked" ascii wide

        // UAC Bypass Technique (T1548.002)
        // They utilize ms-settings to mock a trusted binary
        $uac_bypass = "ms-settings" ascii wide

        // Ransom Note / Branding
        $note_file = "cybervolk_ransom.html" ascii wide
        $group_name = "CyberVolk" ascii wide nocase

        // Registry manipulation for persistence or inhibition
        $reg_taskmgr = "DisableTaskMgr" ascii
        $reg_defender = "DisableAntiSpyware" ascii

    condition:
        // Check for PE File Magic Header (MZ)
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            // Strong Detection: Key File Name + Any Extension or UAC Bypass
            ( $key_file and ( 1 of ($ext*) or $uac_bypass ) ) or

            // Branding Detection: Group Name + Note File + Registry Malice
            ( $group_name and $note_file and 1 of ($reg*) ) or

            // Backup Format Detection: Specific key file format string found in binary
            ( $key_format and 1 of ($ext*) )
        )
}
