import "pe"

rule turla_kazuar_v3_com_visible_app {

    meta:
        author = "Dominik Reichel"
        description = "Detects Turla's Kazuar v3 COM-visible application"
        date = "2026-01-12"
        reference = "https://r136a1.dev/2026/01/14/command-and-evade-turlas-kazuar-v3-loader/"
        hash = "c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9"
        
    strings:
        $a0 = "GetDelegateForFunctionPointer"
        $a1 = "StackFrame"
        $a2 = "GuidAttribute"
        $a3 = "ComVisibleAttribute"
        $a4 = "ClassInterfaceAttribute"
        $a5 = "UnmanagedFunctionPointerAttribute"
        $a6 = "CompilerGeneratedAttribute"
        $a7 = "System.Reflection"
        $a8 = "CallingConvention"
        $a9 = "TargetInvocationException"
        $a10 = "get_InnerException"

        $b0 = "ResourceManager"

    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        pe.imports("mscoree.dll", "_CorDllMain") and
        all of ($a*) and
        filesize < 100KB and not
        $b0
}
