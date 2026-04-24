rule G_Tunneler_SNOWGLAZE_1 {
  meta:
   author = "Google Threat Intelligence Group (GTIG)"
   platforms = "Windows, Linux"
   reference = "https://cloud.google.com/blog/topics/threat-intelligence/unc6692-social-engineering-custom-malware/"
   date = "2026-04-23"
   hash = "2fa987b9ed6ec6d09c7451abd994249dfaba1c5a7da1c22b8407c461e62f7e49"
   
  strings:
    $r1 = /\.connect\(\s{0,25}WS_PROXY_URL/
    $r2 = /"data":\s{0,1}base64\.b64encode\(\w{1,10}\)\.decode\('ascii'\)/
    $r3 = /"type":\s{0,1}"socks_data"/
    $r4 = /await\s{0,1}reader\.read\(\d{2,4}\)/
    $r5 = /"login":\s{0,1}AGENT_LOGIN/
    $r6 = /"password":\s{0,1}AGENT_PASSWORD/
    $r7 = /"uuid":\s{0,1}AGENT_UUID/

    $s1 = ".socks_tcp_to_ws"

  condition:
    5 of ($r*)
    and $s1
}
