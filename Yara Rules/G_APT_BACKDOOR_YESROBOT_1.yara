rule G_APT_BACKDOOR_YESROBOT_1 {
  meta:
    author = "Google Threat Intelligence Group (GTIG)"
    description = "Detects artifacts related to COLDRIVER's YESROBOT campaign."
    creation_date = "2025-10-20"
    date = "2025-10-20"
    reference = "https://cloud.google.com/blog/topics/threat-intelligence/new-malware-russia-coldriver"
    malware = "YESROBOT"
    tags = "COLDRIVER, YESROBOT"
    hash = "bce2a7165ceead4e3601e311c72743e0059ec2cd734ce7acf5cc9f7d8795ba0f"
    version = "1.0"

  strings:
    $s0 = "return f'Mozilla/5.0 {base64.b64encode(str(get_machine_name()).encode()).decode()} {base64.b64encode(str(get_username()).encode()).decode()} {uuid} {get_windows_version()} {get_machine_locale()}'"
    $s1 = "'User-Agent': obtainUA(),"
    $s2 = "url = f\"https://{target}/connect\""
    $s3 = "print(f'{target} is not availible')"
    $s4 = "tgtIp = check_targets(tgtList)"
    $s5 = "cmd_url = f'https://{tgtIp}/command'"
    $s6 = "print('There is no availible servers...')"

  condition:
    4 of them
}
