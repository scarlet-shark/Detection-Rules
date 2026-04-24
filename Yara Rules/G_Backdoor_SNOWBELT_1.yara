rule G_Backdoor_SNOWBELT_1 {
  meta:
      author = "Google Threat Intelligence Group (GTIG)"
      platform = "Windows"
      reference = "https://cloud.google.com/blog/topics/threat-intelligence/unc6692-social-engineering-custom-malware/"
      date = "2026-04-23"
      hash = "7f1d71e1e079f3244a69205588d504ed830d4c473747bb1b5c520634cc5a2477"
      
	strings:
		$str1 = ".importKey(\"raw\",keyMaterial,\"AES-GCM\",!1,[\"decrypt\"])"
		$str2 = ".importKey(\"raw\",keyMaterial,\"AES-GCM\",!1,[\"encrypt\"])"
		$str3 = "sendJsonDataToS3"
		$str4 = "processCommand"
		$str5 = "\"screenshot\"===cmdType"
		$str6 = "\"payload\"===cmdType"
		$str7 = "\"websocket_control\"===cmdType"
		$str8 = "\"open_uri\"===cmdType"
		$str9 = "\"delete_cache\"===cmdType"
		$str10 = "\"payload_download_complete\""
		$str11 = ".s3.us-east-2.amazonaws.com/"
	condition:
		all of them

}
