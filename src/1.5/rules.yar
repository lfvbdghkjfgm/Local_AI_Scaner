rule SuspiciousCommands
{
    meta:
        description = "Legacy broad suspicious command markers"
        severity = "medium"
        version = "1.5"
    strings:
        $cmd1 = "os.system" ascii nocase
        $cmd2 = "subprocess.Popen" ascii nocase
        $wget = "wget " ascii nocase
        $curl = "curl " ascii nocase
    condition:
        any of them
}

rule RCE_Deserialization_Chain
{
    meta:
        description = "Deserialization plus dynamic execution indicators"
        severity = "high"
        category = "rce"
    strings:
        $deserialize_pickle = /pickle\.(load|loads)\s*\(/ ascii nocase
        $deserialize_yaml = /yaml\.load\s*\(/ ascii nocase
        $deserialize_torch = /torch\.load\s*\(/ ascii nocase
        $deserialize_unsafe = "UnsafeLoader" ascii nocase
        $primitive_reduce = "__reduce__" ascii nocase
        $primitive_setstate = "__setstate__" ascii nocase
        $primitive_evalexec = /\b(eval|exec|compile)\s*\(/ ascii nocase
        $primitive_import = /__import__\s*\(/ ascii nocase
    condition:
        (($deserialize_pickle or $deserialize_torch or ($deserialize_yaml and $deserialize_unsafe)) and 1 of ($primitive_*))
}

rule Command_And_Network_Execution
{
    meta:
        description = "Command execution tied to network download or C2 access"
        severity = "high"
        category = "downloader"
    strings:
        $exec_subprocess = /subprocess\.(Popen|run|call|check_output)\s*\(/ ascii nocase
        $exec_system = /os\.system\s*\(/ ascii nocase
        $exec_bash = "/bin/bash -c" ascii nocase
        $exec_sh = "/bin/sh -c" ascii nocase
        $net_curl = "curl " ascii nocase
        $net_wget = "wget " ascii nocase
        $net_urlopen = "urllib.request.urlopen" ascii nocase
        $net_requests = /requests\.(get|post|request)\s*\(/ ascii nocase
    condition:
        (1 of ($exec_*) and 1 of ($net_*))
}

rule Reverse_Shell_Techniques
{
    meta:
        description = "Known reverse shell and interactive C2 command patterns"
        severity = "critical"
        category = "c2"
    strings:
        $channel_dev_tcp = /\/dev\/tcp\/[0-9a-z\.\-]+\/[0-9]{2,5}/ ascii nocase
        $channel_nc_exec = /nc(\.exe|at)?\s+.*-e\s+.*(cmd|sh|bash)/ ascii nocase
        $channel_powershell = /powershell(\.exe)?\s+(-nop|-w\s+hidden)/ ascii nocase
        $action_pty = /pty\.spawn\s*\(/ ascii nocase
        $action_dup2 = /os\.dup2\s*\(/ ascii nocase
        $action_socket = /socket\.(create_connection|socket)\s*\(/ ascii nocase
        $marker_framework = /(meterpreter|cobalt strike|beacon)/ ascii nocase
    condition:
        (($channel_dev_tcp or $channel_nc_exec) and 1 of ($action_*)) or
        ($channel_powershell and $action_socket) or
        $marker_framework
}

rule Obfuscated_Payload_Execution
{
    meta:
        description = "Layered decode/decompress followed by dynamic execution"
        severity = "high"
        category = "obfuscation"
    strings:
        $decoder_base64 = /base64\.(b64decode|urlsafe_b64decode)\s*\(/ ascii nocase
        $decoder_marshal = /marshal\.loads?\s*\(/ ascii nocase
        $decoder_zlib = /zlib\.decompress\s*\(/ ascii nocase
        $decoder_gzip = /gzip\.decompress\s*\(/ ascii nocase
        $decoder_hex = /bytes\.fromhex\s*\(/ ascii nocase
        $exec_eval = /\b(eval|exec)\s*\(/ ascii nocase
        $blob_long_base64 = /[A-Za-z0-9+\/]{180,}={0,2}/ ascii
    condition:
        (2 of ($decoder_*) and $exec_eval) or
        ($blob_long_base64 and $exec_eval and 1 of ($decoder_*))
}

rule Secret_Collection_And_Exfiltration
{
    meta:
        description = "Credential discovery paired with common exfiltration channels"
        severity = "high"
        category = "exfiltration"
    strings:
        $secret_aws = "AWS_SECRET_ACCESS_KEY" ascii nocase
        $secret_hf = "HF_TOKEN" ascii nocase
        $secret_openai = "OPENAI_API_KEY" ascii nocase
        $secret_env = "os.environ" ascii nocase
        $secret_keyring = "keyring.get_password" ascii nocase
        $exfil_discord = /discord(app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/ ascii nocase
        $exfil_telegram = /api\.telegram\.org\/bot[0-9]+:[A-Za-z0-9_-]+\/sendMessage/ ascii nocase
        $exfil_pastebin = /pastebin\.com\/raw\// ascii nocase
        $exfil_smtp = /(smtplib\.SMTP|sendmail\s*\()/ ascii nocase
    condition:
        (1 of ($secret_*) and 1 of ($exfil_*))
}

rule Persistence_And_Defense_Evasion
{
    meta:
        description = "Persistence setup with endpoint protection tampering"
        severity = "high"
        category = "persistence"
    strings:
        $persist_run_key = /HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/ ascii nocase
        $persist_schtasks = /schtasks(\.exe)?\s+\/create/ ascii nocase
        $persist_cron = /(@reboot|crontab\s+-|\/etc\/cron\.)/ ascii nocase
        $persist_startup = /Start Menu\\Programs\\Startup/ ascii nocase
        $evade_defender = /(Set-MpPreference|Add-MpPreference|DisableRealtimeMonitoring)/ ascii nocase
        $evade_chmod_tmp = /chmod\s+\+x\s+\/(tmp|var\/tmp)\// ascii nocase
    condition:
        (1 of ($persist_*) and 1 of ($evade_*))
}

rule Encoded_PowerShell_Payload
{
    meta:
        description = "Encoded PowerShell command execution"
        severity = "critical"
        category = "powershell"
    strings:
        $encoded_cmd = /powershell(\.exe)?\s+.*-(enc|encodedcommand)\s+[A-Za-z0-9+\/=]{40,}/ ascii nocase
        $helper_from_base64 = "FromBase64String(" ascii nocase
        $helper_iex = "Invoke-Expression" ascii nocase
    condition:
        $encoded_cmd or ($helper_from_base64 and $helper_iex)
}

rule Trusted_Remote_Code_Abuse
{
    meta:
        description = "Potential abuse of remote code loading in model pipelines"
        severity = "high"
        category = "supply_chain"
    strings:
        $remote_trust = /trust_remote_code\s*=\s*True/ ascii nocase
        $remote_from_pretrained = /from_pretrained\s*\(/ ascii nocase
        $load_importlib = /importlib\.(import_module|machinery)/ ascii nocase
        $load_tempfile = /(tempfile\.mkdtemp|NamedTemporaryFile)/ ascii nocase
        $load_native = /(ctypes\.CDLL|ctypes\.WinDLL|dlopen)/ ascii nocase
    condition:
        (($remote_trust and $remote_from_pretrained) and 1 of ($load_*)) or
        ($load_importlib and $load_tempfile and $load_native)
}
