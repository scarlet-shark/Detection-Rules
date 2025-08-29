rule SALT_TYPHOON_NEW2_SFTP_CLIENT {
  meta:
    description = "Detects the Salt Typhoon New2 SFTP client. Rule is meant for threat hunting."
    date = "2025-08-26"
    creation_date = "2025-08-26"
    reference = "https://media.defense.gov/2025/Aug/22/2003786665/-1/-1/0/CSA_COUNTERING_CHINA_STATE_ACTORS_COMPROMISE_OF_NETWORKS.PDF"
    version = "1.0"
    tags = "Salt Typhoon"
    hash = "da692ea0b7f24e31696f8b4fe8a130dbbe3c7c15cea6bde24cccc1fb0a73ae9e"

  strings:
    $set_1_1 = "invoke_shell"
    $set_1_2 = "execute_commands"
    $set_1_3 = "cmd_file"
    $set_1_4 = "stop_event"
    $set_1_5 = "decrypt_message"
    $set_2_1 = "COMMANDS_FILE"
    $set_2_2 = "RUN_TIME"
    $set_2_3 = "LOG_FILE"
    $set_2_4 = "ENCRYPTION_PASSWORD"
    $set_2_5 = "FIREWALL_ADDRESS"
    $set_3_1 = "commands.log"
    $set_3_2 = "Executing command: {}"
    $set_3_3 = "Connecting to: {}"
    $set_3_4 = "Network sniffer script."
    $set_3_5 = "tar -czvf - {0} | openssl des3 -salt -k password -out {0}.tar.gz"
    $set_required = { 00 70 61 72 61 6D 69 6B 6F }

  condition:
    $set_required and 4 of ($set_1_*) and 4 of ($set_2_*)
    and 4 of ($set_3_*)
}
