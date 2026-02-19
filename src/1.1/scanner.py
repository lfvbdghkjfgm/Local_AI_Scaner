#!/usr/bin/env python3

import os
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
import pickletools
import hashlib
import subprocess
import json
import traceback
import sys
import platform
import time
import tempfile
import shutil
import re
from pathlib import Path
from typing import Dict, Any
from datetime import datetime
import logging
import numpy as np
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
warnings.filterwarnings('ignore', message='In the future `np.object` will be defined', category=FutureWarning)
try:
    import torch
    HAS_TORCH = True
except Exception:
    torch = None
    HAS_TORCH = False

try:
    import safetensors
    HAS_SAFETENSORS = True
except Exception:
    safetensors = None
    HAS_SAFETENSORS = False

try:
    import tensorflow as tf
    HAS_TENSORFLOW = True
except Exception:
    tf = None
    HAS_TENSORFLOW = False

try:
    from huggingface_hub import HfApi
    HAS_HUGGINGFACE = True
except Exception:
    HfApi = None
    HAS_HUGGINGFACE = False

import warnings


class Scanner:

    def __init__(self, out_form: str = 'text', verb: bool = False, risk_config: Dict[str, Any] = None):
        """Initialize scanner.

        Args:
            out_form: output format
            verb: verbose logging
            risk_config: optional dict to override default risk scoring parameters
        """
        self.out_form = out_form
        self.verb = verb
        self.results: Dict[str, Any] = {}
        self.setup_log()
        default_risk = {
            'format': {'HIGH': 3.0, 'MEDIUM': 2.0, 'LOW': 1.0, 'UNKNOWN': 2.0},
            'weights': {'security_count': 0.7, 'backdoor_count': 0.8, 'warning_critical': 0.5},
            'caps': {'security': 5.0, 'backdoor': 4.0, 'critical': 2.0},
            'normalize_to': 10.0
        }
        if risk_config and isinstance(risk_config, dict):
            merged = default_risk.copy()
            for k, v in risk_config.items():
                if isinstance(v, dict) and isinstance(merged.get(k), dict):
                    merged[k] = {**merged[k], **v}
                else:
                    merged[k] = v
            self.risk_config = merged
        else:
            self.risk_config = default_risk

    def update_risk_config(self, config: Dict[str, Any]):
        if not isinstance(config, dict):
            return
        for k, v in config.items():
            if isinstance(v, dict) and isinstance(self.risk_config.get(k), dict):
                self.risk_config[k].update(v)
            else:
                self.risk_config[k] = v

    def setup_log(self):
        logging.basicConfig(
            level=logging.DEBUG if self.verb else logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        root = logging.getLogger()
        root.setLevel(logging.DEBUG if self.verb else logging.INFO)
        for h in root.handlers:
            h.setLevel(logging.DEBUG if self.verb else logging.INFO)
        self.logger = logging.getLogger(__name__)
        if self.verb:
            self.logger.debug('Verbose logging enabled')

    def scan(self, path: str, scan_type: str = 'full') -> Dict[str, Any]:
        self.results = {
            'scan_id': hashlib.sha256(f'{path}{datetime.now()}'.encode()).hexdigest()[:15],
            'timestamp': datetime.now().isoformat(),
            'path': path,
            'scan_type': scan_type,
            'warnings': [],
            'errors': [],
            'recommendations': []
        }

        try:
            model_type = self.detect_type(path)
            self.results['model_type'] = model_type
            if self.verb:
                self.logger.debug(f'Starting scan for {path} (type={model_type}, scan_type={scan_type})')
            self.results['file_info'] = self.file_info(path)

            pre = self.pre_scan(path, model_type)
            self.results.update(pre)
            if self.verb:
                self.logger.debug('Pre-scan', extra={'pre': pre})

            sha = self.results.get('file_info', {}).get('sha256')
            cached = self._load_cache(sha)
            if cached:
                self.logger.info('Using cached scan result')
                cached['scan_id'] = self.results['scan_id']
                cached['timestamp'] = self.results['timestamp']
                self.results = cached
                return self.results

            if scan_type == 'format':
                self.scan_format(path, model_type)
            elif scan_type == 'security':
                self._run_security_parallel(path, model_type)
            elif scan_type == 'backdoor':
                self.scan_backdoor(path, model_type)
            else:
                self.scan_format(path, model_type)
                self._run_security_parallel(path, model_type)
                self.scan_backdoor(path, model_type)

            self.calculate_risk()

            if sha:
                self._save_cache(sha, self.results)

        except Exception as e:
            self.logger.exception('Scanning failed')
            self.results['errors'].append(f'Scanning failed: {e} | {traceback.format_exc()}')

        return self.results

    def detect_type(self, in_path: str) -> str:
        path = Path(in_path)
        if '/' in in_path and not path.exists():
            return 'huggingface'
        if not path.exists():
            raise FileNotFoundError(f'Model file not found: {in_path}')
        exts = path.suffix.lower()
        mapping = {
            '.pkl': 'pickle', '.pickle': 'pickle', '.pt': 'pytorch', '.pth': 'pytorch',
            '.h5': 'keras', '.keras': 'keras', '.hdf5': 'keras', '.safetensors': 'safetensors',
            '.onnx': 'onnx', '.pb': 'tensorflow', '.zip': 'zip_archive'
        }
        return mapping.get(exts, 'unknown')

    def file_info(self, in_path: str) -> Dict[str, Any]:
        path = Path(in_path)
        if not path.exists():
            return {}
        stat = path.stat()
        h = hashlib.sha256()
        try:
            with open(in_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    h.update(chunk)
            hsh = h.hexdigest()
        except Exception as e:
            self.logger.debug(f'Hashing failed: {e}')
            hsh = ''
        return {
            'file_size': stat.st_size,
            'file_size_mb': round(stat.st_size / (1024**2), 2),
            'mod_time': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'sha256': hsh
        }

    def pre_scan(self, path: str, model_type: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {'quick_signatures': [], 'hf_meta': {}, 'cache_ttl_days': 7}
        out['quick_signatures'] = self.signature_scan(path)
        if model_type == 'huggingface' and HAS_HUGGINGFACE:
            try:
                api = HfApi()
                info = api.model_info(path)
                out['hf_meta'] = {'id': path, 'downloads': getattr(info, 'downloads', None), 'tags': getattr(info, 'tags', [])}
            except Exception as e:
                self.logger.debug(f'HF quick meta failed: {e}')
        return out

    def signature_scan(self, model_path: str) -> list:
        findings = []
        regex_patterns = [r'os\.system', r'subprocess', r'urlopen', r'reverse_shell', r'bind_shell', r'curl\s', r'wget\s']
        try:
            with open(model_path, 'rb') as f:
                sample = f.read(1024 * 1024)
                try:
                    text = sample.decode('latin-1', errors='ignore')
                except Exception:
                    text = ''
                for p in regex_patterns:
                    if re.search(p, text, re.IGNORECASE):
                        findings.append(p)
            try:
                import yara
                rules_path = Path(__file__).parent / 'rules.yar'
                if rules_path.exists():
                    rules = yara.compile(str(rules_path))
                    matches = rules.match(data=sample)
                    for m in matches:
                        findings.append(f'yara:{m.rule}')
            except Exception:
                pass
            if self.verb:
                try:
                    self.logger.debug('Signature scan', extra={'findings': findings, 'sample_len': len(sample)})
                except Exception:
                    self.logger.debug('Signature scan (debug)')
        except Exception as e:
            self.logger.debug(f'signature_scan failed: {e}')
        return findings

    def _cache_path(self) -> Path:
        base = Path(__file__).parent
        cache_dir = base / '.cache'
        try:
            cache_dir.mkdir(exist_ok=True)
        except Exception:
            pass
        return cache_dir / 'scans.json'

    def _load_cache(self, sha: str, max_age_days: int = 7):
        if not sha:
            return None
        path = self._cache_path()
        try:
            if not path.exists():
                if self.verb:
                    self.logger.debug(f'Cache file not found: {path}')
                return None
            with open(path, 'r', encoding='utf-8') as f:
                cache = json.load(f)
            entry = cache.get(sha)
            if not entry:
                if self.verb:
                    self.logger.debug('Cache miss', extra={'sha': sha})
                return None
            ts = entry.get('timestamp')
            if ts:
                then = datetime.fromisoformat(ts)
                if (datetime.now() - then).days > max_age_days:
                    if self.verb:
                        self.logger.debug('Cache entry expired', extra={'sha': sha, 'age_days': (datetime.now() - then).days})
                    return None
            return entry
        except Exception as e:
            self.logger.debug(f'Cache load failed: {e}')
            return None

    def _save_cache(self, sha: str, results: Dict[str, Any]):
        if not sha:
            return
        path = self._cache_path()
        try:
            cache = {}
            if path.exists():
                with open(path, 'r', encoding='utf-8') as f:
                    cache = json.load(f)
            to_store = {k: v for k, v in results.items() if k not in ('pytorch_analysis_raw',)}
            cache[sha] = to_store
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(cache, f, ensure_ascii=False, indent=2)
            if self.verb:
                self.logger.debug('Saved cache entry', extra={'sha': sha, 'path': str(path)})
        except Exception as e:
            self.logger.debug(f'Cache save failed: {e}')

    def _run_security_parallel(self, path: str, type: str):
        issues = []
        funcs = [self.check_file_security, self.check_network_capabilities, self.check_system_access, self.check_known_vulnerabilities]
        if self.verb:
            self.logger.debug('Starting parallel security checks', extra={'checks': [f.__name__ for f in funcs]})
        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = {ex.submit(f, path, type, issues): f for f in funcs}
            for fut in as_completed(futures):
                func = futures.get(fut)
                try:
                    fut.result()
                    if self.verb:
                        self.logger.debug('Completed security check', extra={'check': func.__name__})
                except Exception as e:
                    self.logger.debug(f'Parallel check error: {e}', exc_info=True)
        self.results['security_issues'] = issues

    def scan_format(self, in_path: str, type: str):
        format_risk = {
            'pickle': 'HIGH', 'pytorch': 'MEDIUM', 'keras': 'MEDIUM', 'safetensors': 'LOW',
            'onnx': 'LOW', 'tensorflow': 'MEDIUM', 'huggingface': 'VARIABLE'
        }
        risk = format_risk.get(type, 'UNKNOWN')
        self.results['format_risk'] = risk
        if risk == 'HIGH':
            self.results['warnings'].append(f'Format {type} has HIGH risk')
            self.results['recommendations'].append(f'Consider converting {type} to safetensors/onnx')
        if type == 'pickle':
            self.scan_pickle(in_path)
        elif type == 'keras' and HAS_TENSORFLOW:
            self.scan_keras(in_path)
        elif type == 'pytorch' and HAS_TORCH:
            self.scan_pytorch(in_path)
        elif type == 'safetensors' and HAS_SAFETENSORS:
            self.scan_safet(in_path)
        elif type == 'huggingface':
            self.scan_hugging(in_path)

    def scan_pickle(self, path: str):
        self.logger.info('Analyzing pickle...')
        try:
            file_size_mb = self.results.get('file_info', {}).get('file_size_mb', 0)
            if file_size_mb and file_size_mb > 500:
                self.results['warnings'].append('File too large for deep pickle analysis; skipping detailed parse')
                return
            with open(path, 'rb') as f:
                data = f.read()
            dangerous_ops = ['GLOBAL', 'REDUCE', 'BUILD', 'INST', 'OBJ']
            susp_ops = []
            for op in pickletools.genops(data):
                opcode = op[0]
                op_name = opcode.name
                arg = op[1] if op[1] else ''
                if op_name in dangerous_ops:
                    susp_ops.append({'opcode': op_name, 'argument': str(arg), 'position': op[2]})
                if any(keyword in str(arg).lower() for keyword in ['eval', 'exec', 'compile', 'open', 'file', 'system', 'os.', 'subprocess']):
                    self.results['warnings'].append(f'Dangerous call in pickle: {op_name}({arg})')
            self.results['pickle_analysis'] = {'suspicious_operations': susp_ops, 'total_operations': len(list(pickletools.genops(data)))}
            if susp_ops:
                self.results['warnings'].append(f'Found {len(susp_ops)} suspicious pickle ops')
        except Exception as e:
            self.logger.exception('pickle analysis failed')
            self.results['errors'].append(f'pickle analysis error: {e} | {traceback.format_exc()}')

    def scan_keras(self, path: str):
        if not HAS_TENSORFLOW:
            self.results['errors'].append('TensorFlow not available')
            return
        try:
            meta = self._run_inspector('keras', path)
            lambda_layers = []
            custom_layers = []
            if meta and isinstance(meta, dict) and meta.get('layers'):
                for a, layer in enumerate(meta.get('layers', [])):
                    layer_type = layer.get('type', '')
                    if 'lambda' in layer_type.lower():
                        lambda_layers.append({'index': a, 'name': layer.get('name', ''), 'type': layer_type, 'config': str(layer.get('config', ''))[:200]})
                    elif 'custom' in layer_type.lower() or layer_type not in ['Dense', 'Conv2D', 'LSTM']:
                        custom_layers.append({'index': a, 'name': layer.get('name', ''), 'type': layer_type})
            self.results['keras_analysis'] = {'total_layers': len(meta.get('layers', [])) if meta else None, 'lambda_layers': lambda_layers, 'custom_layers': custom_layers}
            if lambda_layers:
                self.results['warnings'].append(f'Found {len(lambda_layers)} Lambda layers')
            if custom_layers:
                self.results['warnings'].append(f'Found {len(custom_layers)} custom layers')
        except Exception as e:
            self.logger.exception('Keras analysis failed')
            self.results['errors'].append(f'Keras analysis error: {e} | {traceback.format_exc()}')

    def scan_pytorch(self, path: str):
        if not HAS_TORCH:
            self.results['errors'].append('PyTorch not available')
            return
        try:
            meta = self._run_inspector('pytorch', path)
            if not meta:
                self.results['warnings'].append('No metadata from inspector')
                return
            if isinstance(meta, dict) and meta.get('error'):
                self.results['warnings'].append(f"Inspector error: {meta.get('error')}")
                return
            self.results['pytorch_analysis'] = meta
        except Exception as e:
            self.logger.exception('PyTorch analysis failed')
            self.results['errors'].append(f'PyTorch analysis error: {e} | {traceback.format_exc()}')

    def scan_safet(self, path: str):
        if not HAS_SAFETENSORS:
            self.results['errors'].append('safetensors not available')
            return
        try:
            with safetensors.safe_open(path, framework='pt') as f:
                metadata = f.metadata()
                keys = f.keys()
            self.results['safetensors_analysis'] = {'tensors_count': len(keys), 'metadata': metadata, 'safe_format': True}
            self.results['recommendations'].append('Model in safetensors')
        except Exception as e:
            self.logger.exception('safetensors read failed')
            self.results['errors'].append(f'safetensors error: {e} | {traceback.format_exc()}')

    def scan_hugging(self, path: str):
        if not HAS_HUGGINGFACE:
            self.results['errors'].append('huggingface_hub not available')
            return
        try:
            api = HfApi()
            info = api.model_info(path)
            hf_analys = {'model_id': path, 'downloads': getattr(info, 'downloads', None), 'last_modified': getattr(info, 'lastModified', None) and info.lastModified.isoformat(), 'tags': getattr(info, 'tags', []), 'siblings': [sibling.rfilename for sibling in getattr(info, 'siblings', [])]}
            safe_formats = [s for s in hf_analys['siblings'] if s.endswith('.safetensors')]
            unsafe_formats = [s for s in hf_analys['siblings'] if s.endswith(('.bin', '.pkl'))]
            hf_analys['safe_format_files'] = safe_formats
            hf_analys['unsafe_format_files'] = unsafe_formats
            if safe_formats:
                hf_analys['recommendation'] = 'Prefer .safetensors'
            elif unsafe_formats:
                hf_analys['warning'] = 'Contains unsafe formats'
            self.results['huggingface_analysis'] = hf_analys
        except Exception as e:
            self.logger.exception('HF info fetch failed')
            self.results['errors'].append(f'HF error: {e} | {traceback.format_exc()}')

    def check_file_security(self, path: str, type: str, issues: list):
        if type == 'huggingface':
            return
        pathp = Path(path)
        if not pathp.exists():
            return
        file_size_mb = self.results.get('file_info', {}).get('file_size_mb', 0)
        if file_size_mb > 2000:
            issues.append(f'Large file ({file_size_mb} MB)')
        if type == 'zip_archive':
            issues.append('ZIP archive — inspect contents')
        try:
            if platform.system() != 'Windows':
                if pathp.stat().st_mode & 0o777 != 0o644:
                    issues.append('Unusual file permissions')
        except Exception:
            pass

    def check_network_capabilities(self, model_path: str, model_type: str, issues: list):
        if model_type == 'pickle':
            try:
                with open(model_path, 'rb') as f:
                    data = f.read()
                network_keywords = ['http', 'https', 'ftp', 'socket', 'request', 'urlopen', 'connect']
                for op in pickletools.genops(data):
                    arg_str = str(op[1]).lower()
                    if any(keyword in arg_str for keyword in network_keywords):
                        issues.append(f'Network operations in pickle: {arg_str}')
                        break
            except Exception as e:
                self.logger.debug(f'Network analysis failed: {e}')

        if model_type == 'keras' and HAS_TENSORFLOW:
            try:
                meta = self._run_inspector('keras', model_path)
                if meta and isinstance(meta, dict) and meta.get('layers'):
                    for layer in meta.get('layers', []):
                        cfg = str(layer.get('config', '')).lower()
                        if any(k in cfg for k in ['url', 'http', 'request']):
                            issues.append(f"Layer {layer.get('name','?')} references network resources")
            except Exception as e:
                self.logger.debug(f'Keras network check failed: {e}')

    def check_system_access(self, model_path: str, model_type: str, issues: list):
        dangerous_keywords = ['os.', 'subprocess', 'sys.', 'shutil', 'open(', 'file(', 'eval', 'exec', 'compile', 'import', '__import__', 'getattr']
        if model_type == 'pickle':
            try:
                with open(model_path, 'rb') as f:
                    data = f.read()
                for op in pickletools.genops(data):
                    arg_str = str(op[1])
                    for keyword in dangerous_keywords:
                        if keyword in arg_str:
                            issues.append(f'Dangerous system call: {arg_str}')
                            break
            except Exception as e:
                self.logger.debug(f'System access check failed: {e}')

    def check_known_vulnerabilities(self, model_path: str, model_type: str, issues: list):
        if model_type == 'huggingface':
            return
        known = ['reverse_shell', 'bind_shell', 'web_delivery', 'meterpreter', 'beacon', 'cobalt_strike']
        try:
            with open(model_path, 'rb') as f:
                sample = f.read(1024 * 1024)
                raw = sample.decode('latin-1', errors='ignore')
                content = raw.lower()


            suffix = Path(model_path).suffix.lower()
            is_text_file = suffix in ('.json', '.yaml', '.yml', '.txt', '')
            has_shadow_marker = False
            if is_text_file:
                try:
                    if '"shadow_logic"' in raw or "'shadow_logic'" in raw or 'shadow_logic' in content:
                        has_shadow_marker = True
                except Exception:
                    has_shadow_marker = False

            for sig in known:
                if sig in content:
                    if has_shadow_marker:
                        issues.append(f'Potential shadow logic marker: {sig}')
                    else:
                        issues.append(f'Known trojan signature: {sig}')
        except Exception as e:
            self.logger.debug(f'Known vulns check failed: {e}')

    def scan_backdoor(self, path: str, type: str):
        backdoors = {'performed_checks': [], 'suspicious_patterns': [], 'recommendations': [], 'advanced_analysis_required': True}
        self.check_trigger_patterns(path, type, backdoors)
        self.check_anomalous_behavior(path, type, backdoors)
        self.check_model_integrity(path, type, backdoors)
        self.check_training_data_anomalies(path, type, backdoors)
        self.results['backdoor_analysis'] = backdoors
        if backdoors['suspicious_patterns']:
            self.results['warnings'].extend(backdoors['suspicious_patterns'])
        if backdoors['recommendations']:
            self.results['recommendations'].extend(backdoors['recommendations'])

    def check_trigger_patterns(self, model_path: str, model_type: str, backdoor_checks: dict):
        backdoor_checks['performed_checks'].append('trigger_patterns')
        try:
            if model_type == 'pytorch' and HAS_TORCH:
                meta = self._run_inspector('pytorch', model_path)
                if not meta or meta.get('error'):
                    backdoor_checks['suspicious_patterns'].append('Failed to inspect tensors')
                    return
                tensor_stats = meta.get('tensor_stats', {})
                analyzed = 0
                for key, stats in tensor_stats.items():
                    if analyzed >= 5:
                        break
                    extreme_count = stats.get('extreme_count', 0)
                    unique_ratio = stats.get('unique_ratio', 1.0)
                    if extreme_count and extreme_count > max(10, stats.get('size', 0) * 0.001):
                        backdoor_checks['suspicious_patterns'].append(f'Extreme values in {key}: {extreme_count}')
                    if unique_ratio < 0.1:
                        backdoor_checks['suspicious_patterns'].append(f'Low unique ratio in {key}: {unique_ratio:.3f}')
                    analyzed += 1
            elif model_type == 'keras' and HAS_TENSORFLOW:
                meta = self._run_inspector('keras', model_path)
                if meta and meta.get('layers'):
                    analyzed_layers = 0
                    for layer in meta.get('layers', []):
                        weights = layer.get('weights', [])
                        for w in weights:
                            shape = w.get('shape') if isinstance(w, dict) else None
                            if shape and analyzed_layers < 3:
                                if len(shape) > 1 and shape[-1] > 1000:
                                    backdoor_checks['suspicious_patterns'].append(f"Layer {layer.get('name','?')} large dim: {tuple(shape)}")
                                analyzed_layers += 1
                                if analyzed_layers >= 3:
                                    break
                        if analyzed_layers >= 3:
                            break
        except Exception as e:
            self.logger.debug(f'Trigger pattern analysis failed: {e}')

    def check_anomalous_behavior(self, model_path: str, model_type: str, backdoor_checks: dict):
        backdoor_checks['performed_checks'].append('anomalous_behavior')
        if model_type in ['keras', 'pytorch'] and self.is_computer_vision_model(model_path, model_type):
            backdoor_checks['suspicious_patterns'].append('CV model — test with patch triggers')
            backdoor_checks['recommendations'].append('Run trigger patch tests')

    def is_computer_vision_model(self, model_path: str, model_type: str) -> bool:
        vision_keywords = ['conv', 'conv2d', 'convolution', 'cnn', 'resnet', 'vgg', 'mobilenet', 'efficientnet', 'vision', 'image']
        try:
            if model_type == 'keras' and HAS_TENSORFLOW:
                meta = self._run_inspector('keras', model_path)
                if meta and meta.get('layers'):
                    layer_str = ' '.join([f"{l.get('type','')} {l.get('name','')}" for l in meta.get('layers', [])]).lower()
                    return any(k in layer_str for k in vision_keywords)
            if model_type == 'pytorch' and HAS_TORCH:
                meta = self._run_inspector('pytorch', model_path)
                if meta and meta.get('keys'):
                    keys_str = ' '.join(meta.get('keys')).lower()
                    return any(k in keys_str for k in vision_keywords)
        except Exception as e:
            self.logger.debug(f'CV detection failed: {e}')
        return False

    def check_model_integrity(self, model_path: str, model_type: str, backdoor_checks: dict):
        backdoor_checks['performed_checks'].append('model_integrity')
        if model_type == 'huggingface':
            backdoor_checks['recommendations'].append('Verify HF model signature')
        else:
            file_info = self.results.get('file_info', {})
            if file_info.get('sha256'):
                backdoor_checks['file_integrity'] = {'sha256': file_info['sha256'], 'verified': 'UNKNOWN'}

    def check_training_data_anomalies(self, model_path: str, model_type: str, backdoor_checks: dict):
        backdoor_checks['performed_checks'].append('training_data_anomalies')
        if model_type == 'huggingface' and HAS_HUGGINGFACE:
            hf = self.results.get('huggingface_analysis', {})
            tags = hf.get('tags', [])
            suspicious = ['exclude_from_train', 'toxic', 'unsafe', 'malicious']
            found = [t for t in tags if t in suspicious]
            if found:
                backdoor_checks['suspicious_patterns'].append(f'Suspicious tags: {found}')

    def calculate_risk(self):
        warnings_count = len(self.results.get('warnings', []))
        errors_count = len(self.results.get('errors', []))
        format_risk = self.results.get('format_risk', 'UNKNOWN')

        fmt_scores = self.risk_config.get('format', {})
        w = self.risk_config.get('weights', {})
        caps = self.risk_config.get('caps', {})

        format_contrib = float(fmt_scores.get(format_risk, fmt_scores.get('UNKNOWN', 2.0)))

        security = self.results.get('security_issues', [])
        security_contrib = min(len(security) * float(w.get('security_count', 0.7)), float(caps.get('security', 5.0)))

        back = self.results.get('backdoor_analysis', {})
        susp = back.get('suspicious_patterns', [])
        backdoor_contrib = min(len(susp) * float(w.get('backdoor_count', 0.8)), float(caps.get('backdoor', 4.0)))

        critical_raw = 0.0
        for msg in self.results.get('warnings', []):
            if any(k in msg.lower() for k in ['reverse_shell', 'trojan', 'backdoor', 'eval', 'exec', 'os.']):
                critical_raw += float(w.get('warning_critical', 0.5))
        critical_contrib = min(critical_raw, float(caps.get('critical', 2.0)))

        raw_score = format_contrib + security_contrib + backdoor_contrib + critical_contrib

        normalize_to = float(self.risk_config.get('normalize_to', 10.0))
        max_possible = float(caps.get('security', 5.0)) + float(caps.get('backdoor', 4.0)) + float(caps.get('critical', 2.0)) + max(fmt_scores.values())
        if max_possible <= 0:
            normalized = 0.0
        else:
            normalized = round(min(raw_score, max_possible) / max_possible * normalize_to, 2)

        if normalized >= (0.9 * normalize_to):
            level = 'CRITICAL'
        elif normalized >= (0.6 * normalize_to):
            level = 'HIGH'
        elif normalized >= (0.3 * normalize_to):
            level = 'MEDIUM'
        else:
            level = 'LOW'

        self.results['risk_assessment'] = {
            'raw_score': round(raw_score, 3),
            'score': normalized,
            'scale': normalize_to,
            'level': level,
            'warnings_count': warnings_count,
            'errors_count': errors_count,
            'security_issues_count': len(security),
            'backdoor_suspicions_count': len(susp),
            'breakdown': {
                'format_threat': round(format_contrib, 3),
                'security_threats': round(security_contrib, 3),
                'backdoor_patterns': round(backdoor_contrib, 3),
                'critical_threats': round(critical_contrib, 3)
            },
            'contributors': {
                'format': {'value': format_risk, 'score': format_contrib},
                'security_count': {'count': len(security), 'per_item': float(w.get('security_count', 0.7))},
                'backdoor_count': {'count': len(susp), 'per_item': float(w.get('backdoor_count', 0.8))},
                'critical_warnings': {'count': int(critical_raw / max(1e-6, float(w.get('warning_critical', 0.5)))), 'per_item': float(w.get('warning_critical', 0.5))}
            },
            'config_used': self.risk_config
        }

    def _run_inspector(self, model_type: str, model_path: str, timeout: int = 15):
        try:
            cmd = [sys.executable, str(Path(__file__).parent / 'safe_loader.py'), '--type', model_type, '--path', model_path]
            env = os.environ.copy()
            for k in ['HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy']:
                env.pop(k, None)
            if self.verb:
                self.logger.debug('Invoking inspector subprocess', extra={'cmd': cmd, 'timeout': timeout})
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
            out = proc.stdout.strip()
            if self.verb:
                self.logger.debug('Inspector subprocess finished', extra={'returncode': proc.returncode, 'stderr_len': len(proc.stderr or ''), 'stdout_len': len(out)})
            if proc.returncode != 0:
                err = proc.stderr.strip() or out
                self.logger.debug(f'Inspector non-zero exit: {err}')
                return {'error': err}
            if not out:
                if self.verb:
                    self.logger.debug('Inspector returned no output')
                return None
            try:
                return json.loads(out)
            except Exception:
                self.logger.debug('Invalid JSON from inspector', extra={'raw': out[:200]})
                return {'error': 'invalid_output'}
        except subprocess.TimeoutExpired:
            self.logger.debug('Inspector timed out')
            return {'error': 'timeout'}
        except Exception as e:
            self.logger.debug(f'Inspector failed: {e}')
            return {'error': str(e)}
