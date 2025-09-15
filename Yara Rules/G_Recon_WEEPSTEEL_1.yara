rule G_Recon_WEEPSTEEL_1 {
    meta:
    	author = "Mandiant"
      creation_date = "2025-09-03"
      date = "2025-09-03"
      reference = "https://cloud.google.com/blog/topics/threat-intelligence/viewstate-deserialization-zero-day-vulnerability"
      hash = "a566cceaf9a66332470a978a234a8a8e2bbdd4d6aa43c2c75c25a80b3b744307"

    strings:
        $v_w = "<input type=\"hidden\" name=\"__VIEWSTATE\" id=\"__VIEWSTATE\" value=" wide
        $v_a = "<input type=\"hidden\" name=\"__VIEWSTATE\" id=\"__VIEWSTATE\" value="
        $v_b64_w = "<input type=\"hidden\" name=\"__VIEWSTATE\" id=\"__VIEWSTATE\" value=" base64wide
        $v_b64_a = "<input type=\"hidden\" name=\"__VIEWSTATE\" id=\"__VIEWSTATE\" value=" base64
        $s2 = "Services\\Tcpip\\Parameters" wide
        $s3 = "GetOperatingSystemInformation"
        $s4 = "GetSystemInformation"
        $s5 = "GetNetworkAdapterInformation"
        $s6 = "GetAllNetworkInterfaces"
        $s7 = "GetIPProperties"
        $s8 = "GetPhysicalAddress"
        $s9 = "GetDomainNameFromRegistry"

        $c1 = "Aes" fullword
        $c2 = "CreateEncryptor" fullword
        $c3 = "System.Security.Cryptography" fullword
        $c4 = "ToBase64String" fullword

        $guid = "6d5a95da-0ffe-4303-bb2c-39e182335a9f"

    condition:
        uint16(0) == 0x5a4d and
        (
            (all of ($c*) and 7 of ($s*)) or
            ($guid and (any of ($v*)))
        )
}
