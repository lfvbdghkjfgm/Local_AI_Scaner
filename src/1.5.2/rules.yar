rule SuspiciousCommands
{
    meta:
        description = "Broad suspicious command invocation markers"
        severity = "medium"
        category = "execution"
        version = "1.5.2"
    strings:
        $cmd1 = "os.system" ascii nocase
        $cmd2 = "subprocess.Popen" ascii nocase
        $cmd3 = "subprocess.run" ascii nocase
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
        version = "1.5.2"
    strings:
        $deserialize_pickle = /pickle\.(load|loads)\s*\(/ ascii nocase
        $deserialize_yaml = /yaml\.load\s*\(/ ascii nocase
        $deserialize_torch = /torch\.load\s*\(/ ascii nocase
        $deserialize_dill = /dill\.loads?\s*\(/ ascii nocase
        $deserialize_joblib = /joblib\.load\s*\(/ ascii nocase
        $deserialize_unsafe = "UnsafeLoader" ascii nocase
        $primitive_reduce = "__reduce__" ascii nocase
        $primitive_setstate = "__setstate__" ascii nocase
        $primitive_evalexec = /\b(eval|exec|compile)\s*\(/ ascii nocase
        $primitive_import = /__import__\s*\(/ ascii nocase
    condition:
        (
            ($deserialize_pickle or $deserialize_torch or $deserialize_dill or $deserialize_joblib or ($deserialize_yaml and $deserialize_unsafe))
            and 1 of ($primitive_*)
        )
}

rule Command_And_Network_Execution
{
    meta:
        description = "Command execution tied to network access or downloader behavior"
        severity = "high"
        category = "downloader"
        version = "1.5.2"
    strings:
        $exec_subprocess = /subprocess\.(Popen|run|call|check_output)\s*\(/ ascii nocase
        $exec_system = /os\.system\s*\(/ ascii nocase
        $exec_bash = "/bin/bash -c" ascii nocase
        $exec_sh = "/bin/sh -c" ascii nocase
        $net_curl = "curl " ascii nocase
        $net_wget = "wget " ascii nocase
        $net_urlopen = "urllib.request.urlopen" ascii nocase
        $net_requests = /requests\.(get|post|request)\s*\(/ ascii nocase
        $net_iwr = /(Invoke-WebRequest|iwr\s+http)/ ascii nocase
    condition:
        (1 of ($exec_*) and 1 of ($net_*))
}

rule Reverse_Shell_Techniques
{
    meta:
        description = "Known reverse shell and interactive C2 patterns"
        severity = "critical"
        category = "c2"
        version = "1.5.2"
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
        description = "Layered decode/decompress operations followed by dynamic execution"
        severity = "high"
        category = "obfuscation"
        version = "1.5.2"
    strings:
        $decoder_base64 = /base64\.(b64decode|urlsafe_b64decode)\s*\(/ ascii nocase
        $decoder_marshal = /marshal\.loads?\s*\(/ ascii nocase
        $decoder_zlib = /zlib\.decompress\s*\(/ ascii nocase
        $decoder_gzip = /gzip\.decompress\s*\(/ ascii nocase
        $decoder_hex = /bytes\.fromhex\s*\(/ ascii nocase
        $exec_eval = /\b(eval|exec)\s*\(/ ascii nocase
    condition:
        (2 of ($decoder_*) and $exec_eval) or
        ($decoder_base64 and $decoder_marshal and $exec_eval)
}

rule Secret_Collection_And_Exfiltration
{
    meta:
        description = "Credential discovery paired with common exfiltration channels"
        severity = "high"
        category = "exfiltration"
        version = "1.5.2"
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
        $exfil_slack = /hooks\.slack\.com\/services\/[A-Za-z0-9\/_-]+/ ascii nocase
    condition:
        (1 of ($secret_*) and 1 of ($exfil_*))
}

rule Credential_File_Harvest_And_Exfil
{
    meta:
        description = "Credential file harvesting plus upload/exfil behavior"
        severity = "high"
        category = "credential_access"
        version = "1.5.2"
    strings:
        $harvest_aws = /\.aws\/credentials/ ascii nocase
        $harvest_kube = /kube\/config/ ascii nocase
        $harvest_ssh = /\.ssh\/(id_rsa|id_ed25519)/ ascii nocase
        $harvest_git = /\.git-credentials/ ascii nocase
        $harvest_env = /\.env/ ascii nocase
        $upload_requests = /requests\.(post|put)\s*\(/ ascii nocase
        $upload_multipart = /files\s*=\s*\{/ ascii nocase
        $upload_s3 = /(boto3\.client\(\"s3\"|upload_file\()/ ascii nocase
        $upload_http = /(http(s)?:\/\/|webhook)/ ascii nocase
    condition:
        (1 of ($harvest_*) and 1 of ($upload_*))
}

rule Persistence_And_Defense_Evasion
{
    meta:
        description = "Persistence setup with endpoint protection tampering"
        severity = "high"
        category = "persistence"
        version = "1.5.2"
    strings:
        $persist_run_key = /HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/ ascii nocase
        $persist_schtasks = /schtasks(\.exe)?\s+\/create/ ascii nocase
        $persist_cron = /(@reboot|crontab\s+-|\/etc\/cron\.)/ ascii nocase
        $persist_startup = /Start Menu\\Programs\\Startup/ ascii nocase
        $persist_systemd = /(systemctl\s+enable|\/etc\/systemd\/system\/)/ ascii nocase
        $evade_defender = /(Set-MpPreference|Add-MpPreference|DisableRealtimeMonitoring)/ ascii nocase
        $evade_chmod_tmp = /chmod\s+\+x\s+\/(tmp|var\/tmp)\// ascii nocase
        $evade_disable_av = /(Stop-Service\s+WinDefend|sc\s+stop\s+WinDefend)/ ascii nocase
    condition:
        (1 of ($persist_*) and 1 of ($evade_*))
}

rule Encoded_PowerShell_Payload
{
    meta:
        description = "Encoded PowerShell command execution"
        severity = "critical"
        category = "powershell"
        version = "1.5.2"
    strings:
        $encoded_cmd = /powershell(\.exe)?\s+.*-(enc|encodedcommand)\s+[A-Za-z0-9+\/=]{40,}/ ascii nocase
        $helper_from_base64 = "FromBase64String(" ascii nocase
        $helper_iex = "Invoke-Expression" ascii nocase
        $hidden_window = /powershell(\.exe)?\s+.*(-w\s+hidden|-windowstyle\s+hidden)/ ascii nocase
    condition:
        $encoded_cmd or ($helper_from_base64 and $helper_iex) or ($hidden_window and $helper_iex)
}

rule Trusted_Remote_Code_Abuse
{
    meta:
        description = "Potential abuse of remote code loading in model pipelines"
        severity = "high"
        category = "supply_chain"
        version = "1.5.2"
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

rule Dynamic_Download_And_Execution_Stager
{
    meta:
        description = "Downloader that saves payload to temp path and executes it"
        severity = "critical"
        category = "stager"
        version = "1.5.2"
    strings:
        $download_requests = /requests\.(get|post)\s*\(/ ascii nocase
        $download_urlretrieve = /urllib\.request\.urlretrieve\s*\(/ ascii nocase
        $download_iwr = /(Invoke-WebRequest|Start-BitsTransfer)/ ascii nocase
        $write_temp = /(tempfile\.(mkstemp|mkdtemp)|\/tmp\/|%TEMP%|AppData\\Local\\Temp)/ ascii nocase
        $run_subprocess = /subprocess\.(Popen|run|call)\s*\(/ ascii nocase
        $run_powershell = /powershell(\.exe)?\s+/ ascii nocase
        $run_shell = /(cmd\.exe\s+\/c|\/bin\/(sh|bash)\s+-c)/ ascii nocase
    condition:
        (1 of ($download_*) and $write_temp and 1 of ($run_*))
}

rule Archive_Extraction_Then_Execution
{
    meta:
        description = "Archive extraction followed by dynamic code loading/execution"
        severity = "high"
        category = "loader"
        version = "1.5.2"
    strings:
        $extract_zip = /zipfile\.ZipFile\s*\(/ ascii nocase
        $extract_tar = /tarfile\.open\s*\(/ ascii nocase
        $extract_all = /(extractall\s*\(|extract\s*\()/ ascii nocase
        $load_py = /(runpy\.run_path|importlib\.import_module|exec\s*\()/ ascii nocase
        $load_bin = /(ctypes\.CDLL|os\.system|subprocess\.)/ ascii nocase
    condition:
        (($extract_zip or $extract_tar) and $extract_all and (1 of ($load_*)))
}

rule Native_Library_Load_Execution
{
    meta:
        description = "Native library loading potentially combined with remote or temp staging"
        severity = "high"
        category = "native_loader"
        version = "1.5.2"
    strings:
        $native_ctypes = /(ctypes\.(CDLL|WinDLL|PyDLL)|ffi\.dlopen)/ ascii nocase
        $native_loadlib = /(LoadLibraryA|LoadLibraryW|dlopen\()/ ascii nocase
        $stage_temp = /(tempfile|\/tmp\/|\\Temp\\)/ ascii nocase
        $stage_url = /(https?:\/\/|ftp:\/\/)/ ascii nocase
        $drop_write = /(open\s*\(.*(wb|ab)|write\s*\()/ ascii nocase
    condition:
        ((1 of ($native_*) and 1 of ($stage_*) and $drop_write) or
         (1 of ($native_*) and $stage_url))
}
