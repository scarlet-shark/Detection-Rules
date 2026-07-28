rule IOT_DDoS_tengu_sample {

   meta:
       description = "Mirai-derived Linux DDoS botnet: DGA+AEAD C2, proxy, Android/IPFS dropper, watchdog/reboot bricking"
       hash = "897226af37990fa60f25fea00b0509faa0e78d8bee10875c23b9b6ab0b8faed9"
       author = "Nozomi Networks Labs"
       date = "2026-07-07"
       reference = "https://www.nozominetworks.com/blog/tengu-a-modernized-mirai-that-doesnt-want-to-leave"

   strings:

       $masq1 = "[kworker/%d:%d]" ascii
       $masq2 = "/usr/lib/systemd/systemd-journald" ascii
       $masq3 = "/dev/shm/.journal" ascii
       $brick = "ELFOOD" ascii
       $svc1  = "chud-daemon" ascii
       $svc2  = "chud-watchdog" ascii
       $svc3  = "chud-scheduler" ascii
       $tengu = "/etc/init.d/tengu" ascii
       $upd   = "/tmp/.up" ascii
       $prox  = "/tmp/.proxy.pid" ascii
       $ipfs  = "GET /ipfs/%s HTTP/1.0" ascii
       $apk1  = "aapt dump badging '%s' 2>/dev/null" ascii
       $apk2  = "am start -n '%s/.MainActivity' 2>/dev/null" ascii
       $cron  = "* * * * * root [ -x /proc/self/exe ] && /proc/self/exe" ascii
       $wd    = "/dev/watchdog0" ascii
       $tsrc  = "TSource Engine Query" ascii

   condition:
       uint32(0) == 0x464c457f and 4 of them

}
