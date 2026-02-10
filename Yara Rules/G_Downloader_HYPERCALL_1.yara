rule G_Downloader_HYPERCALL_1 {
	meta:
		author = "Google Threat Intelligence Group (GTIG)"
    description = "Detects UNC1069's HYPERCALL malware."
    malware = "HYPERCALL"
    intrusion_set = "UNC1069"
    tags = "UNC1069, HYPERCALL"
    date = "2025-10-24"
		date_created = "2025-10-24"
		date_modified = "2025-10-24"
    hash = "03f00a143b8929585c122d490b6a3895d639c17d92C2223917e3a9ca1b8d30f9"
		rev = 1
    reference = "https://cloud.google.com/blog/topics/threat-intelligence/unc1069-targets-cryptocurrency-ai-social-engineering"

	strings:
		$go_build = "Go build ID:"
		$go_inf = "Go buildinf:"
		$lib1 = "/inject_mac/inject.go"
		$lib2 = "github.com/gorilla/websocket"
		$func1 = "t_loader/inject_mac.Inject"
		$func2 = "t_loader/common.rc4_decode"
		$c1 = { 48 BF 00 AC 23 FC 06 00 00 00 0F 1F 00 E8 ?? ?? ?? ?? 48 8B 94 24 ?? ?? ?? ?? 48 8B 32 48 8B 52 ?? 48 8B 76 ?? 48 89 CF 48 89 D9 48 89 C3 48 89 D0 FF D6 }
		$c2 = { 48 89 D6 48 F7 EA 48 01 DA 48 01 CA 48 C1 FA 1A 48 C1 FE 3F 48 29 F2 48 69 D2 00 E1 F5 05 48 29 D3 48 8D 04 19 }

	condition:
		(uint32(0) == 0xfeedface or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe) and all of ($go*) and any of ($lib*) and any of ($func*) and all of ($c*)
}
