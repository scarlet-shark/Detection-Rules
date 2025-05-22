rule APT28_HEADLACE_CORE {
  meta:
    description = "Detects HEADLACE core batch scripts"
    author = "Joint Government Cybersecurity Advisory"
    creation_date = "2025-05-21"
    reference = "https://media.defense.gov/2025/May/21/2003719846/-1/-1/0/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.PDF"
    tags = "APT28, HEADLACE"    

  strings:
    $chcp = "chcp 65001" ascii
    $headless = "start \"\" msedge --headless=new --disable-gpu" ascii
    $command_1 = "taskkill /im msedge.exe /f" ascii
    $command_2 = "whoami>\"%programdata%" ascii
    $command_3 = "timeout" ascii
    $command_4 = "copy \"%programdata%\\" ascii
    $non_generic_del_1 = "del /q /f \"%programdata%" ascii
    $non_generic_del_3 = "del /q /f \"%userprofile%\\Downloads\\" ascii
    $generic_del = "del /q /f" ascii
  condition:
    (
      $chcp
      and
      $headless
    )
    and
    (
      1 of ($non_generic_del_*)
      or
      ($generic_del)
      or
      3 of ($command_*)
    )
}
