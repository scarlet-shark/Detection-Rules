rule Moonrise_RAT_20260312 {
  meta:
      description = "Detects Moonrise RAT malware based on unique functional and behavioral strings."
      author = "Alec Dhuse"
      date = "2026-03-12"
      reference = "https://medium.com/@scarletshark/analysts-brief-moonrise-rat-bfbea85ae62a"
      hash = "082fdd964976afa6f9c5d8239f74990b24df3dfa0c95329c6e9f75d33681b9f4"
      malware = "Moonrise RAT"

    strings:
        // Specific Go-compiled function names observed in the binary
        $func1 = "fun_bsod"
        $func2 = "fun_shutdown"
        $func3 = "voltage_drop"
        $func4 = "screenshot"

        // WebSocket and Communication strings
        $ws1 = "websocket" ascii wide
        $ws2 = "gorilla/websocket" ascii

    condition:
        uint16(0) == 0x5A4D and // MZ Header (Windows PE)
        (
            (3 of ($func*)) or
            (all of ($ws*) and 2 of ($func*))
        )
}
