rule G_Backdoor_PLASMAGRID_Strings_1 {

	meta:
    description = "Detects PLASMAGRID Malware"
		author = "Google Threat Intelligence Group (GTIG)"
    reference = "https://cloud.google.com/blog/topics/threat-intelligence/coruna-powerful-ios-exploit-kit"
    date = "2026-03-03"

	strings:
		$ = "com.plasma.appruntime.appdiscovery"
		$ = "com.plasma.appruntime.downloadmanager"
		$ = "com.plasma.appruntime.hotupdatemanager"
		$ = "com.plasma.appruntime.modulestore"
		$ = "com.plasma.appruntime.netconfig"
		$ = "com.plasma.bundlemapper"
		$ = "com.plasma.event.upload.serial"
		$ = "com.plasma.notes.monitor"
		$ = "com.plasma.photomonitor"
		$ = "com.plasma.PLProcessStateDetector"
		$ = "plasma_heartbeat_monitor"
		$ = "plasma_injection_dispatcher"
		$ = "plasma_ipc_processor"
		$ = "plasma_%@.jpg"
		$ = "/var/mobile/Library/Preferences/com.plasma.photomonitor.plist"
		$ = "helion_ipc_handler"
		$ = "PLInjectionStateInfo"
		$ = "PLExploitationInterface"

	condition:
		1 of them
}
