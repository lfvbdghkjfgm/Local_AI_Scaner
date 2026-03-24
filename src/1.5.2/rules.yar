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

rule Python_Dynamic_Import_Execution_Chain
{
    meta:
        description = "Dynamic import plus runtime execution/codegen chain"
        severity = "high"
        category = "rce"
        version = "1.5.2-ext"
    strings:
        $import_dyn_1 = /importlib\.(import_module|machinery|util\.spec_from_file_location)\s*\(/ ascii nocase
        $import_dyn_2 = /__import__\s*\(/ ascii nocase
        $exec_dyn_1 = /\b(eval|exec|compile)\s*\(/ ascii nocase
        $chain_dyn_1 = /types\.FunctionType\s*\(/ ascii nocase
        $chain_dyn_2 = /ast\.parse\s*\(/ ascii nocase
        $chain_dyn_3 = /marshal\.loads?\s*\(/ ascii nocase
        $chain_dyn_4 = /base64\.(b64decode|urlsafe_b64decode)\s*\(/ ascii nocase
    condition:
        (1 of ($import_dyn_*) and $exec_dyn_1 and 1 of ($chain_dyn_*))
}

rule Pickle_Persistence_Hook_Abuse
{
    meta:
        description = "Pickle persistence hooks combined with dangerous primitives"
        severity = "high"
        category = "deserialization"
        version = "1.5.2-ext"
    strings:
        $pickle_hook_1 = /persistent_load\s*\(/ ascii nocase
        $pickle_hook_2 = /find_class\s*\(/ ascii nocase
        $pickle_hook_3 = /(dispatch_table|copyreg\.pickle)/ ascii nocase
        $pickle_primitive_1 = /(__reduce__|__setstate__)/ ascii nocase
        $pickle_primitive_2 = /(os\.system|subprocess\.)/ ascii nocase
        $pickle_primitive_3 = /\b(eval|exec)\s*\(/ ascii nocase
    condition:
        (1 of ($pickle_hook_*) and 1 of ($pickle_primitive_*))
}

rule Unsafe_Deserialization_Framework_Abuse
{
    meta:
        description = "Unsafe deserialization frameworks tied to execution primitives"
        severity = "high"
        category = "deserialization"
        version = "1.5.2-ext"
    strings:
        $deserialize_fw_1 = /yaml\.(load|unsafe_load)\s*\(/ ascii nocase
        $deserialize_fw_2 = /ruamel\.yaml/ ascii nocase
        $deserialize_fw_3 = /jsonpickle\.decode\s*\(/ ascii nocase
        $deserialize_fw_4 = /pickle\.loads?\s*\(/ ascii nocase
        $deserialize_fw_5 = /dill\.loads?\s*\(/ ascii nocase
        $deserialize_fw_6 = /cloudpickle\.loads?\s*\(/ ascii nocase
        $deserialize_fw_7 = /joblib\.load\s*\(/ ascii nocase
        $unsafe_exec_1 = /\b(eval|exec|compile)\s*\(/ ascii nocase
        $unsafe_exec_2 = /__import__\s*\(/ ascii nocase
        $unsafe_exec_3 = /subprocess\.(Popen|run|call)\s*\(/ ascii nocase
    condition:
        (2 of ($deserialize_fw_*) and 1 of ($unsafe_exec_*))
}

rule Torch_Hub_Remote_Load_Abuse
{
    meta:
        description = "Remote model/code fetch in torch pipelines with execution path"
        severity = "high"
        category = "supply_chain"
        version = "1.5.2-ext"
    strings:
        $torch_hub_1 = /torch\.hub\.load\s*\(/ ascii nocase
        $torch_hub_2 = /load_state_dict_from_url\s*\(/ ascii nocase
        $torch_hub_3 = /huggingface_hub\.(hf_hub_download|snapshot_download)\s*\(/ ascii nocase
        $torch_net_1 = /requests\.(get|post|request)\s*\(/ ascii nocase
        $torch_net_2 = /urllib\.request\.(urlopen|urlretrieve)\s*\(/ ascii nocase
        $torch_net_3 = /(curl|wget)\s+https?:\/\// ascii nocase
        $torch_exec_1 = /torch\.load\s*\(/ ascii nocase
        $torch_exec_2 = /importlib\.import_module\s*\(/ ascii nocase
        $torch_exec_3 = /ctypes\.(CDLL|WinDLL|PyDLL)/ ascii nocase
    condition:
        (1 of ($torch_hub_*) and 1 of ($torch_net_*) and 1 of ($torch_exec_*))
}

rule ONNX_Custom_Operator_Loading_Abuse
{
    meta:
        description = "ONNX runtime custom-op/native library execution indicators"
        severity = "high"
        category = "native_loader"
        version = "1.5.2-ext"
    strings:
        $onnx_core_1 = /(onnxruntime\.InferenceSession|InferenceSession\s*\()/ ascii nocase
        $onnx_custom_1 = /register_custom_ops_library\s*\(/ ascii nocase
        $onnx_custom_2 = /(CustomOp|customop|PyOp)/ ascii nocase
        $onnx_custom_3 = /(SessionOptions|execution_provider)/ ascii nocase
        $onnx_native_1 = /ctypes\.(CDLL|WinDLL|PyDLL)/ ascii nocase
        $onnx_native_2 = /(LoadLibraryA|LoadLibraryW|dlopen\()/ ascii nocase
    condition:
        (($onnx_core_1 and 1 of ($onnx_custom_*)) or (1 of ($onnx_custom_*) and 1 of ($onnx_native_*)))
}

rule TensorFlow_Custom_Op_Loading_Abuse
{
    meta:
        description = "TensorFlow custom-op loading or py_function execution abuse"
        severity = "high"
        category = "native_loader"
        version = "1.5.2-ext"
    strings:
        $tf_loader_1 = /tf\.load_op_library\s*\(/ ascii nocase
        $tf_exec_1 = /tf\.(py_function|numpy_function)\s*\(/ ascii nocase
        $tf_exec_2 = /tf\.raw_ops\./ ascii nocase
        $tf_exec_3 = /keras\.layers\.Lambda/ ascii nocase
        $tf_native_1 = /ctypes\.(CDLL|WinDLL|PyDLL)/ ascii nocase
        $tf_native_2 = /(LoadLibraryA|LoadLibraryW|dlopen\()/ ascii nocase
    condition:
        (($tf_loader_1 and 1 of ($tf_exec_*)) or (1 of ($tf_exec_*) and 1 of ($tf_native_*)))
}

rule JIT_Runtime_Codegen_Abuse
{
    meta:
        description = "Runtime compilation staged in temp paths and executed"
        severity = "high"
        category = "execution"
        version = "1.5.2-ext"
    strings:
        $jit_compile_1 = /numba\.(jit|cfunc|njit)\s*\(/ ascii nocase
        $jit_compile_2 = /torch\.utils\.cpp_extension\.load\s*\(/ ascii nocase
        $jit_compile_3 = /(gcc|clang|cl\.exe)\s+.*(-shared|\/LD)/ ascii nocase
        $jit_compile_4 = /(nvcc|rustc|go build)\s+/ ascii nocase
        $jit_stage_1 = /(tempfile\.mkdtemp|NamedTemporaryFile|\/tmp\/|\\Temp\\)/ ascii nocase
        $jit_stage_2 = /(open\s*\(.*(wb|ab)|write\s*\()/ ascii nocase
        $jit_run_1 = /subprocess\.(Popen|run|call)\s*\(/ ascii nocase
        $jit_run_2 = /os\.system\s*\(/ ascii nocase
        $jit_run_3 = /(ctypes\.CDLL|dlopen\()/ ascii nocase
    condition:
        (1 of ($jit_compile_*) and 1 of ($jit_stage_*) and 1 of ($jit_run_*))
}

rule AMSI_ETW_Bypass_Techniques
{
    meta:
        description = "PowerShell AMSI or ETW bypass techniques"
        severity = "critical"
        category = "defense_evasion"
        version = "1.5.2-ext"
    strings:
        $amsi_1 = /(AmsiScanBuffer|AmsiUtils|amsiInitFailed)/ ascii nocase
        $amsi_2 = /(System\.Management\.Automation\.AmsiUtils|BypassAmsi)/ ascii nocase
        $etw_1 = /(EtwEventWrite|PSEtwLogProvider|EventWrite)/ ascii nocase
        $etw_2 = /(DisableETW|PatchETW|EtwProvider)/ ascii nocase
        $bypass_1 = /(VirtualProtect|WriteProcessMemory|NtProtectVirtualMemory)/ ascii nocase
        $bypass_2 = /(Add-Type\s+-TypeDefinition|Reflection\.Assembly)/ ascii nocase
    condition:
        ((1 of ($amsi_*) and 1 of ($bypass_*)) or (1 of ($etw_*) and 1 of ($bypass_*)))
}

rule Process_Injection_Windows_APIs
{
    meta:
        description = "Classic remote process injection API sequence"
        severity = "critical"
        category = "injection"
        version = "1.5.2-ext"
    strings:
        $inject_1 = /(OpenProcess|NtOpenProcess)/ ascii nocase
        $inject_2 = /(VirtualAllocEx|NtAllocateVirtualMemory)/ ascii nocase
        $inject_3 = /(WriteProcessMemory|NtWriteVirtualMemory)/ ascii nocase
        $inject_4 = /(CreateRemoteThread|NtCreateThreadEx|QueueUserAPC)/ ascii nocase
        $inject_5 = /(SetThreadContext|ResumeThread|SuspendThread)/ ascii nocase
    condition:
        3 of ($inject_*)
}

rule Credential_Dumping_LSASS_Access
{
    meta:
        description = "LSASS access and credential dumping indicators"
        severity = "critical"
        category = "credential_access"
        version = "1.5.2-ext"
    strings:
        $lsass_1 = /lsass\.exe/ ascii nocase
        $lsass_2 = /MiniDumpWriteDump/ ascii nocase
        $lsass_3 = /procdump(\.exe)?\s+-ma\s+lsass/ ascii nocase
        $dump_aux_1 = /(sekurlsa::logonpasswords|mimikatz)/ ascii nocase
        $dump_aux_2 = /(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION|SeDebugPrivilege)/ ascii nocase
        $dump_aux_3 = /(comsvcs\.dll,\s*MiniDump)/ ascii nocase
    condition:
        (1 of ($lsass_*) and 1 of ($dump_aux_*))
}

rule Browser_Credential_Theft
{
    meta:
        description = "Browser credential harvesting with decryption and exfil"
        severity = "high"
        category = "credential_access"
        version = "1.5.2-ext"
    strings:
        $browser_path_1 = /AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data/ ascii nocase
        $browser_path_2 = /AppData\\Roaming\\Mozilla\\Firefox\\Profiles/ ascii nocase
        $browser_path_3 = /(\bCookies\b|\bWeb Data\b|\bLogin Data\b)/ ascii nocase
        $browser_path_4 = /(Local State|key4\.db|logins\.json)/ ascii nocase
        $browser_crypto_1 = /CryptUnprotectData\s*\(/ ascii nocase
        $browser_crypto_2 = /(AES\.new|PBKDF2HMAC|win32crypt)/ ascii nocase
        $browser_exfil_1 = /requests\.(post|put)\s*\(/ ascii nocase
        $browser_exfil_2 = /(discord(app)?\.com\/api\/webhooks|api\.telegram\.org\/bot)/ ascii nocase
        $browser_exfil_3 = /(smtplib\.SMTP|ftp:\/\/|http(s)?:\/\/)/ ascii nocase
    condition:
        (1 of ($browser_path_*) and 1 of ($browser_crypto_*) and 1 of ($browser_exfil_*))
}

rule Cloud_Metadata_Service_Abuse
{
    meta:
        description = "Cloud instance metadata probing with programmatic retrieval"
        severity = "high"
        category = "credential_access"
        version = "1.5.2-ext"
    strings:
        $meta_endpoint_1 = /169\.254\.169\.254\/latest\/meta-data/ ascii nocase
        $meta_endpoint_2 = /metadata\.google\.internal\/computeMetadata\/v1/ ascii nocase
        $meta_endpoint_3 = /169\.254\.169\.254\/metadata\/instance/ ascii nocase
        $meta_endpoint_4 = /169\.254\.170\.2\/v2\/credentials/ ascii nocase
        $meta_request_1 = /requests\.(get|post|request)\s*\(/ ascii nocase
        $meta_request_2 = /urllib\.request\.urlopen\s*\(/ ascii nocase
        $meta_request_3 = /(curl|wget)\s+http:\/\/169\.254\./ ascii nocase
        $meta_header_1 = /(X-aws-ec2-metadata-token|Metadata-Flavor:\s*Google)/ ascii nocase
    condition:
        ((1 of ($meta_endpoint_*) or $meta_header_1) and 1 of ($meta_request_*))
}

rule Data_Staging_Archive_Exfiltration
{
    meta:
        description = "Archiving or packaging followed by outbound upload/exfiltration"
        severity = "high"
        category = "exfiltration"
        version = "1.5.2-ext"
    strings:
        $stage_pack_1 = /zipfile\.ZipFile\s*\(/ ascii nocase
        $stage_pack_2 = /tarfile\.open\s*\(/ ascii nocase
        $stage_pack_3 = /shutil\.make_archive\s*\(/ ascii nocase
        $stage_pack_4 = /(7z|rar)\s+a\s+/ ascii nocase
        $stage_encode_1 = /base64\.(b64encode|urlsafe_b64encode)\s*\(/ ascii nocase
        $stage_exfil_1 = /requests\.(post|put)\s*\(/ ascii nocase
        $stage_exfil_2 = /files\s*=\s*\{/ ascii nocase
        $stage_exfil_3 = /(http(s)?:\/\/|webhook|s3:\/\/)/ ascii nocase
    condition:
        ((1 of ($stage_pack_*) and 1 of ($stage_exfil_*)) or
         (1 of ($stage_pack_*) and $stage_encode_1 and 1 of ($stage_exfil_*)))
}

rule DNS_Tunneling_And_Exfil
{
    meta:
        description = "DNS-based tunneling/exfil indicators"
        severity = "high"
        category = "c2"
        version = "1.5.2-ext"
    strings:
        $dns_tool_1 = /nslookup(\.exe)?\s+/ ascii nocase
        $dns_tool_2 = /\bdig\s+/ ascii nocase
        $dns_tool_3 = /Resolve-DnsName\s+/ ascii nocase
        $dns_data_1 = /[A-Za-z0-9+\/]{40,}\.[A-Za-z0-9\.\-]{3,}/ ascii nocase
        $dns_data_2 = /(TXT\s+|--type=TXT|type=txt)/ ascii nocase
        $dns_send_1 = /\b(subdomain|chunk|exfil)\b/ ascii nocase
        $dns_send_2 = /(base64\.(b64encode|urlsafe_b64encode)|hex\(\))/ ascii nocase
    condition:
        (1 of ($dns_tool_*) and 1 of ($dns_data_*) and 1 of ($dns_send_*))
}

rule Tor_Proxy_C2_Channel
{
    meta:
        description = "TOR/proxy based command-and-control channel indicators"
        severity = "high"
        category = "c2"
        version = "1.5.2-ext"
    strings:
        $tor_endpoint_1 = /\.onion/ ascii nocase
        $tor_endpoint_2 = /(127\.0\.0\.1:9050|127\.0\.0\.1:9150|socks5h?:\/\/127\.0\.0\.1)/ ascii nocase
        $tor_endpoint_3 = /(tor2web|torsocks)/ ascii nocase
        $tor_client_1 = /(stem\.control|TorRequest|PySocks|socks\.setdefaultproxy)/ ascii nocase
        $tor_client_2 = /proxies\s*=\s*\{.*socks5/ ascii nocase
        $tor_client_3 = /curl\s+--proxy\s+socks5/ ascii nocase
    condition:
        (1 of ($tor_endpoint_*) and 1 of ($tor_client_*))
}

rule SSH_Lateral_Movement_Automation
{
    meta:
        description = "Automated SSH movement and remote command execution"
        severity = "high"
        category = "lateral_movement"
        version = "1.5.2-ext"
    strings:
        $ssh_tool_1 = /paramiko\.SSHClient/ ascii nocase
        $ssh_tool_2 = /fabric\.Connection/ ascii nocase
        $ssh_tool_3 = /sshpass\s+-p\s+/ ascii nocase
        $ssh_exec_1 = /exec_command\s*\(/ ascii nocase
        $ssh_exec_2 = /scp\s+.*@/ ascii nocase
        $ssh_exec_3 = /ssh\s+.*(StrictHostKeyChecking=no|BatchMode=yes)/ ascii nocase
        $ssh_exec_4 = /(known_hosts|authorized_keys)/ ascii nocase
    condition:
        (1 of ($ssh_tool_*) and 1 of ($ssh_exec_*))
}

rule SMB_WMI_PsExec_Lateral_Movement
{
    meta:
        description = "SMB/WMI/PsExec remote execution indicators"
        severity = "high"
        category = "lateral_movement"
        version = "1.5.2-ext"
    strings:
        $lmv_1 = /psexec(\.exe)?\s+\\\\/ ascii nocase
        $lmv_2 = /wmic(\.exe)?\s+\/node:/ ascii nocase
        $lmv_3 = /winrm(\.cmd)?\s+invoke/ ascii nocase
        $lmv_4 = /(smbexec|wmiexec|atexec)/ ascii nocase
        $lmv_5 = /sc(\.exe)?\s+\\\\.*\s+create/ ascii nocase
    condition:
        2 of ($lmv_*)
}

rule Ransomware_Bulk_Encryption_Behavior
{
    meta:
        description = "Bulk encryption workflow and ransom-note behavior"
        severity = "critical"
        category = "impact"
        version = "1.5.2-ext"
    strings:
        $ransom_crypto_1 = /(cryptography\.fernet|Fernet\s*\()/ ascii nocase
        $ransom_crypto_2 = /(AES\.new|ChaCha20|Salsa20|RSA\.import_key)/ ascii nocase
        $ransom_crypto_3 = /(pyAesCrypt|nacl\.secret)/ ascii nocase
        $ransom_enum_1 = /os\.walk\s*\(/ ascii nocase
        $ransom_enum_2 = /rglob\s*\(/ ascii nocase
        $ransom_enum_3 = /glob\.glob\s*\(.*\*\*/ ascii nocase
        $ransom_write_1 = /(open\s*\(.*(wb|ab)|write\s*\()/ ascii nocase
        $ransom_write_2 = /(os\.rename|Path\.rename|shutil\.move)\s*\(/ ascii nocase
        $ransom_write_3 = /(os\.remove|Path\.unlink|unlink\s*\()/ ascii nocase
        $ransom_note_1 = /(README_FOR_DECRYPT|HOW_TO_DECRYPT|DECRYPT_INSTRUCTIONS|RECOVER_FILES)/ ascii nocase
        $ransom_note_2 = /(bitcoin|monero)\s+(wallet|address)/ ascii nocase
    condition:
        ((1 of ($ransom_crypto_*) and 1 of ($ransom_enum_*) and 1 of ($ransom_write_*)) or
         (1 of ($ransom_note_*) and 1 of ($ransom_write_*)))
}

rule Backup_And_Shadow_Copy_Deletion
{
    meta:
        description = "Backup/shadow copy deletion to prevent recovery"
        severity = "critical"
        category = "impact"
        version = "1.5.2-ext"
    strings:
        $backup_del_1 = /vssadmin(\.exe)?\s+delete\s+shadows/ ascii nocase
        $backup_del_2 = /wmic(\.exe)?\s+shadowcopy\s+delete/ ascii nocase
        $backup_del_3 = /wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup)/ ascii nocase
        $backup_del_4 = /bcdedit(\.exe)?\s+\/set\s+\{default\}\s+recoveryenabled\s+no/ ascii nocase
        $backup_del_5 = /bcdedit(\.exe)?\s+\/set\s+\{default\}\s+bootstatuspolicy\s+ignoreallfailures/ ascii nocase
    condition:
        1 of ($backup_del_*)
}

rule Log_Tampering_And_Coverup
{
    meta:
        description = "Event/log history tampering and cleanup actions"
        severity = "high"
        category = "defense_evasion"
        version = "1.5.2-ext"
    strings:
        $log_tamper_1 = /wevtutil(\.exe)?\s+cl\s+/ ascii nocase
        $log_tamper_2 = /auditpol(\.exe)?\s+\/clear/ ascii nocase
        $log_tamper_3 = /(Clear-EventLog|Remove-EventLog)/ ascii nocase
        $log_tamper_4 = /(history\s+-c|unset\s+HISTFILE)/ ascii nocase
        $log_tamper_5 = /rm\s+-rf\s+\/var\/log\// ascii nocase
        $log_tamper_6 = /journalctl\s+--vacuum-(time|size)/ ascii nocase
    condition:
        1 of ($log_tamper_*)
}

rule CryptoMiner_Execution_Indicators
{
    meta:
        description = "Cryptominer binaries/pools/runtime options"
        severity = "high"
        category = "resource_abuse"
        version = "1.5.2-ext"
    strings:
        $miner_bin_1 = /(xmrig|xmr-stak|minerd|cpuminer|ethminer)/ ascii nocase
        $miner_bin_2 = /(rig-id|donate-level|--coin)/ ascii nocase
        $miner_pool_1 = /(stratum\+tcp:\/\/|stratum\+ssl:\/\/)/ ascii nocase
        $miner_pool_2 = /(pool\.supportxmr|nanopool|minexmr|2miners|nicehash)/ ascii nocase
        $miner_start_1 = /(nicehash|monero|randomx|cryptonight)/ ascii nocase
        $miner_start_2 = /(taskset|--threads|--cpu-max-threads-hint)/ ascii nocase
    condition:
        ((1 of ($miner_bin_*) and 1 of ($miner_pool_*)) or
         (1 of ($miner_pool_*) and 1 of ($miner_start_*)))
}

rule Anti_VM_Sandbox_Evasion
{
    meta:
        description = "Virtualization/sandbox fingerprinting with evasive flow"
        severity = "high"
        category = "defense_evasion"
        version = "1.5.2-ext"
    strings:
        $vm_marker_1 = /(vmware|virtualbox|vboxservice|qemu|xen|kvm)/ ascii nocase
        $vm_marker_2 = /(vboxguest|vmtoolsd|prl_tools)/ ascii nocase
        $vm_marker_3 = /(biosversion|baseboardmanufacturer|systemproductname)/ ascii nocase
        $vm_marker_4 = /(innotek gmbh|virtual machine)/ ascii nocase
        $vm_action_1 = /(Get-WmiObject\s+Win32_(BIOS|ComputerSystem)|wmic\s+bios)/ ascii nocase
        $vm_action_2 = /(cpuid|rdtsc|hypervisor|sleep\s*\(\s*[3-9][0-9]{2,}\s*\))/ ascii nocase
        $vm_action_3 = /(if\s+.*(vmware|virtualbox).*(exit|return))/ ascii nocase
        $vm_action_4 = /(IsDebuggerPresent|CheckRemoteDebuggerPresent)/ ascii nocase
    condition:
        (2 of ($vm_marker_*) and 1 of ($vm_action_*))
}

rule CI_CD_Secret_Theft
{
    meta:
        description = "CI/CD token collection and outbound transfer patterns"
        severity = "high"
        category = "credential_access"
        version = "1.5.2-ext"
    strings:
        $cicd_secret_1 = "GITHUB_TOKEN" ascii nocase
        $cicd_secret_2 = "GH_TOKEN" ascii nocase
        $cicd_secret_3 = "GITLAB_TOKEN" ascii nocase
        $cicd_secret_4 = "CI_JOB_TOKEN" ascii nocase
        $cicd_secret_5 = "JENKINS_URL" ascii nocase
        $cicd_secret_6 = "JENKINS_HOME" ascii nocase
        $cicd_secret_7 = "ACTIONS_RUNTIME_TOKEN" ascii nocase
        $cicd_exfil_1 = /requests\.(post|put)\s*\(/ ascii nocase
        $cicd_exfil_2 = /(curl|wget)\s+https?:\/\// ascii nocase
        $cicd_exfil_3 = /git\s+push\s+https?:\/\/[^ ]+:[^ ]+@/ ascii nocase
        $cicd_exfil_4 = /(discord(app)?\.com\/api\/webhooks|api\.telegram\.org\/bot)/ ascii nocase
    condition:
        (1 of ($cicd_secret_*) and 1 of ($cicd_exfil_*))
}

rule Kubernetes_Cluster_Abuse
{
    meta:
        description = "Kubernetes service account abuse and privileged operations"
        severity = "high"
        category = "cloud_abuse"
        version = "1.5.2-ext"
    strings:
        $k8s_access_1 = /\/var\/run\/secrets\/kubernetes\.io\/serviceaccount\/token/ ascii nocase
        $k8s_access_2 = /KUBERNETES_SERVICE_HOST/ ascii nocase
        $k8s_access_3 = /kubectl\s+config\s+view/ ascii nocase
        $k8s_access_4 = /kubeconfig/ ascii nocase
        $k8s_abuse_1 = /kubectl\s+create\s+clusterrolebinding/ ascii nocase
        $k8s_abuse_2 = /kubectl\s+auth\s+can-i/ ascii nocase
        $k8s_abuse_3 = /kubectl\s+exec\s+.*--\s*(sh|bash)/ ascii nocase
        $k8s_abuse_4 = /(curl|wget)\s+https?:\/\/kubernetes\.default/ ascii nocase
    condition:
        (1 of ($k8s_access_*) and 1 of ($k8s_abuse_*))
}

rule Container_Breakout_Primitives
{
    meta:
        description = "Container escape via Docker socket/nsenter/host mount abuse"
        severity = "critical"
        category = "container_escape"
        version = "1.5.2-ext"
    strings:
        $ctr_socket_1 = "/var/run/docker.sock" ascii nocase
        $ctr_socket_2 = /unix:\/\/\/var\/run\/docker\.sock/ ascii nocase
        $ctr_escape_1 = /docker\s+(-H\s+unix:\/\/\/var\/run\/docker\.sock\s+)?run\s+.*(--privileged|-v\s+\/:\/host)/ ascii nocase
        $ctr_escape_2 = /nsenter\s+--target\s+1\s+--mount/ ascii nocase
        $ctr_escape_3 = /chroot\s+\/host/ ascii nocase
        $ctr_escape_4 = /mount\s+.*\/proc\/1\/ns/ ascii nocase
        $ctr_escape_5 = /(crictl\s+exec|ctr\s+tasks\s+exec)/ ascii nocase
    condition:
        (1 of ($ctr_socket_*) and 1 of ($ctr_escape_*))
}

rule Linux_PrivEsc_Persistence_Primitives
{
    meta:
        description = "Linux privilege escalation and persistence shell primitives"
        severity = "high"
        category = "privilege_escalation"
        version = "1.5.2-ext"
    strings:
        $lpe_1 = /chmod\s+\+s\s+\/(usr\/bin|bin)\// ascii nocase
        $lpe_2 = /setcap\s+cap_setuid\+ep/ ascii nocase
        $lpe_3 = /echo\s+.*>>\s*\/etc\/sudoers/ ascii nocase
        $lpe_4 = /echo\s+.*>>\s*\/root\/\.ssh\/authorized_keys/ ascii nocase
        $lpe_5 = /systemctl\s+enable\s+.*\.service/ ascii nocase
        $lpe_6 = /crontab\s+-l.*\|\|.*echo/ ascii nocase
    condition:
        2 of ($lpe_*)
}

rule SupplyChain_Install_Hook_Abuse
{
    meta:
        description = "Package install hooks that execute remote payload logic"
        severity = "medium"
        category = "supply_chain"
        version = "1.5.2-ext"
    strings:
        $pkg_hook_1 = /(setup\(\s*|setuptools\.setup\s*\()/ ascii nocase
        $pkg_hook_2 = /(cmdclass\s*=|entry_points\s*=|console_scripts)/ ascii nocase
        $pkg_hook_3 = /(post_install|install\.run|build_ext\.run)/ ascii nocase
        $pkg_exec_1 = /subprocess\.(Popen|run|call)\s*\(/ ascii nocase
        $pkg_exec_2 = /os\.system\s*\(/ ascii nocase
        $pkg_exec_3 = /pip\s+install\s+.*(http|git\+)/ ascii nocase
        $pkg_exec_4 = /(curl|wget)\s+https?:\/\// ascii nocase
        $pkg_remote_1 = /(http(s)?:\/\/|git\+http|--extra-index-url|--trusted-host)/ ascii nocase
        $pkg_remote_2 = /download_url\s*=/ ascii nocase
        $pkg_remote_3 = /dependency_links\s*=/ ascii nocase
    condition:
        (1 of ($pkg_hook_*) and 1 of ($pkg_exec_*) and 1 of ($pkg_remote_*))
}

rule Scheduled_Persistence_Dropper
{
    meta:
        description = "Scheduled task/cron/systemd persistence with staged command execution"
        severity = "high"
        category = "persistence"
        version = "1.5.2-ext"
    strings:
        $sched_1 = /schtasks(\.exe)?\s+\/create/ ascii nocase
        $sched_2 = /at(\.exe)?\s+[0-9:]+\s+/ ascii nocase
        $sched_3 = /(crontab\s+-e|@reboot)/ ascii nocase
        $sched_4 = /\/etc\/systemd\/system\/.*\.service/ ascii nocase
        $sched_stage_1 = /(curl|wget|Invoke-WebRequest|Start-BitsTransfer)/ ascii nocase
        $sched_stage_2 = /(powershell(\.exe)?\s+|cmd\.exe\s+\/c|\/bin\/(sh|bash)\s+-c)/ ascii nocase
        $sched_stage_3 = /(tempfile|\/tmp\/|\\Temp\\)/ ascii nocase
    condition:
        (1 of ($sched_*) and 1 of ($sched_stage_*))
}

rule LOLBAS_Execution_Abuse
{
    meta:
        description = "Windows LOLBAS binaries used to fetch or execute payloads"
        severity = "high"
        category = "execution"
        version = "1.5.2-ext"
    strings:
        $lolbin_1 = /rundll32(\.exe)?\s+.*(javascript:|mshtml,RunHTMLApplication)/ ascii nocase
        $lolbin_2 = /regsvr32(\.exe)?\s+.*(\/i:|scrobj\.dll)/ ascii nocase
        $lolbin_3 = /mshta(\.exe)?\s+https?:\/\// ascii nocase
        $lolbin_4 = /certutil(\.exe)?\s+.*(-urlcache|-decode|-encode)/ ascii nocase
        $lolbin_5 = /bitsadmin(\.exe)?\s+\/transfer/ ascii nocase
        $lolbin_6 = /installutil(\.exe)?\s+.*\.exe/ ascii nocase
        $lolbin_7 = /wmic(\.exe)?\s+process\s+call\s+create/ ascii nocase
        $lolbin_8 = /forfiles(\.exe)?\s+.*\/c\s+/ ascii nocase
        $lol_payload_1 = /(http(s)?:\/\/|ftp:\/\/)/ ascii nocase
        $lol_payload_2 = /(cmd\.exe\s+\/c|powershell(\.exe)?\s+|\/bin\/sh\s+-c)/ ascii nocase
        $lol_payload_3 = /(FromBase64String|encodedcommand|Invoke-Expression)/ ascii nocase
    condition:
        (1 of ($lolbin_*) and 1 of ($lol_payload_*))
}

rule API_Hooking_Inline_Patch_Techniques
{
    meta:
        description = "User-mode API hooking or inline patching indicators"
        severity = "high"
        category = "defense_evasion"
        version = "1.5.2-ext"
    strings:
        $hook_api_1 = /(SetWindowsHookEx|SetWinEventHook|WH_KEYBOARD_LL|WH_MOUSE_LL)/ ascii nocase
        $hook_api_2 = /(GetProcAddress|LoadLibraryA|LoadLibraryW)/ ascii nocase
        $hook_api_3 = /(InlineHook|Detours|MinHook|IAT Hook|EAT Hook)/ ascii nocase
        $hook_api_4 = /(NtQuerySystemInformation|ZwQuerySystemInformation)/ ascii nocase
        $hook_mem_1 = /(VirtualProtect|NtProtectVirtualMemory|mprotect)/ ascii nocase
        $hook_mem_2 = /(WriteProcessMemory|RtlMoveMemory|memcpy\s*\()/ ascii nocase
        $hook_mem_3 = /(PAGE_EXECUTE_READWRITE|RWX)/ ascii nocase
        $hook_mem_4 = /(trampoline|shellcode|patch bytes)/ ascii nocase
    condition:
        (1 of ($hook_api_*) and 1 of ($hook_mem_*))
}
