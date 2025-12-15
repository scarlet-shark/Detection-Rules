rule G_Backdoor_COMPOOD_1 {

	meta:
    description = "Detects COMPOOD malware."
    author = "Google Threat Intelligence Group (GTIG)"
    date = "2025-12-11"
    date_modified = "2025-12-11"
    md5 = "d3e7b234cf76286c425d987818da3304"
    hash = "d3e7b234cf76286c425d987818da3304"
    reference = "https://cloud.google.com/blog/topics/threat-intelligence/threat-actors-exploit-react2shell-cve-2025-55182"
    malware = "COMPOOD"
    rev = "1"

	strings:
		$strings_1 = "ShellLinux.Shell"
		$strings_2 = "ShellLinux.Exec_shell"
		$strings_3 = "ProcessLinux.sendBody"
		$strings_4 = "ProcessLinux.ProcessTask"
		$strings_5 = "socket5Quick.StopProxy"
		$strings_6 = "httpAndTcp"
		$strings_7 = "clean.readFile"
		$strings_8 = "/sys/kernel/mm/transparent_hugepage/hpage_pmd_size"
		$strings_9 = "/proc/self/auxv"
		$strings_10 = "/dev/urandom"
		$strings_11 = "client finished"
		$strings_12 = "github.com/creack/pty.Start"

	condition:
		uint32(0) == 0x464C457f and 8 of ($strings_*)
}
