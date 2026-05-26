import "pe"

rule Lazarus_DPAPILoader_Hunting {
  meta:
    description = "Hunting rule to detect DPAPILoader, a loader used to load RemotePE."
    author      = "Fox-IT / NCC Group"
    reference   = "https://blog.fox-it.com/2026/05/22/remotepe-the-lazarus-rat-that-lives-in-memory/"
    hash        = "4f6ae0110cf652264293df571d66955f7109e3424a070423b5e50edc3eb43874"
    date        = "2026-05-22"

  strings:
    $msg_1 = "[!] Could not allocate memory at the desired base!\n"
    $msg_2 = "[!] Virtual section size is out ouf bounds: "
    $msg_3 = "[!] Invalid relocDir pointer\n"
    $msg_4 = "[-] Not supported relocations format at %d: %d\n"
    $msg_5 = "[!] Cannot fill imports into 32 bit PE via 64 bit loader!\n"

  condition:
    any of them and pe.imports("Crypt32.dll", "CryptUnprotectData")
}
