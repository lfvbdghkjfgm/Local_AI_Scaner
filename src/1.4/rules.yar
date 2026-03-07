rule SuspiciousCommands
{
    strings:
        $cmd1 = "os.system"
        $cmd2 = "subprocess.Popen"
        $wget = "wget "
        $curl = "curl "
    condition:
        any of them
}
