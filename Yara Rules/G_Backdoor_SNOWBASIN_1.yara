rule G_Backdoor_SNOWBASIN_1 {
  meta:
    author = "Google Threat Intelligence Group (GTIG)"
    platform = "Windows"
    reference = "https://cloud.google.com/blog/topics/threat-intelligence/unc6692-social-engineering-custom-malware/"
    date = "2026-04-23"
    hash = "c8940de8cb917abe158a826a1d08f1083af517351d01642e6c7f324d0bba1eb8"
    
  strings:
    $path1 = "self.path == '/probe':"
    $path2 = "self.path == '/stream':"
    $path3 = "self.path == '/buffer':"
    $path4 = "self.path == '/flush':"
    $path5 = "self.path == '/commit':"
    $path6 = "self.path == '/capture':"
    $path7 = "self.path == '/gc':"

    $func1 = "self.handle_stream("
    $func2 = "self.handle_buffer("
    $func3 = "self.handle_flush("
    $func4 = "self.handle_commit("

    $s1 = "self.wfile.write(info_msg"
    $s2 = "selected_port), WebServerHandler) as httpd:"
    $s3 = "ThreadedTCPServer(socketserver.ThreadingMixIn"
    $s4 = "httpd.serve_forever()"


  condition:
    filesize<1MB and (
      (all of ($s*) and 6 of ($path*, $func*)) or
      (8 of ($path*, $func*)) or
      10 of them
    )
}
