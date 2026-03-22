rule rmcej_otb_payload {
    meta:
        description = "Detects rmcej%otb% shuffle-cipher JS payload injected into config files"
        author = "OpenSourceMalware.com"
        date = "2026-03-07"
        severity = "high"
        reference = "https://opensourcemalware.com/blog/polinrider-attack"
        tags = "PolinRider, Contagious Interview"

    strings:
        $marker   = "rmcej%otb%"
        $global   = "global['!']"
        $seed1    = "2857687"
        $seed2    = "2667686"
        $varname  = "_$_1e42"

    condition:
        $marker or ($global and $seed1) or ($varname and $seed2)
}
