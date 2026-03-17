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

try:
    import yara
    HAS_YARA = True
    YARA_IMPORT_ERROR = ''
except Exception as e:
    yara = None
    HAS_YARA = False
    YARA_IMPORT_ERROR = str(e)

class Scanner:
    CACHE_SCHEMA_VERSION = 3
    RISK_ENGINE_VERSION = "2.8"
    CACHE_TTL_DAYS = 7
    MAX_SIGNATURE_SAMPLE_BYTES = 4 * 1024 * 1024
    YARA_MATCH_TIMEOUT = 20

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
            'weights': {
                'security_count': 1.2,
                'backdoor_count': 1.4,
                'warning_critical': 2.0,
                'network_ops': 1.5,
                'system_calls': 1.8,
                'shadow_pattern': 0.5,
                'yara_medium': 0.8,
                'yara_high': 1.6,
                'yara_critical': 2.2
            },
            'caps': {'security': 8.0, 'backdoor': 8.0, 'critical': 8.0},
            'normalize_to': 10.0,
            'effective_max_raw': 16.0
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
        self._yara_rules = None
        self._yara_engine_error = ''
        self._last_signature_details = []
        self._init_signature_engine()

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

    def _init_signature_engine(self):
        self._yara_rules = None
        self._yara_engine_error = ''
        if not HAS_YARA:
            self._yara_engine_error = f'yara-python unavailable: {YARA_IMPORT_ERROR or "import failed"}'
            return
        rules_path = Path(__file__).parent / 'rules.yar'
        if not rules_path.exists():
            self._yara_engine_error = f'rules file not found: {rules_path}'
            return
        try:
            self._yara_rules = yara.compile(filepath=str(rules_path))
        except Exception as e:
            self._yara_engine_error = f'failed to compile rules: {e}'

    def _signature_engine_status(self) -> Dict[str, Any]:
        return {
            'regex_enabled': True,
            'yara_available': HAS_YARA,
            'yara_rules_loaded': self._yara_rules is not None,
            'yara_error': self._yara_engine_error or None,
        }

    @staticmethod
    def _normalize_yara_meta(meta: Dict[str, Any]) -> Dict[str, str]:
        severity = str(meta.get('severity', 'medium')).strip().lower()
        if severity not in {'low', 'medium', 'high', 'critical'}:
            severity = 'medium'
        category = str(meta.get('category', 'generic')).strip().lower() or 'generic'
        description = str(meta.get('description', '')).strip()
        return {'severity': severity, 'category': category, 'description': description}

    @staticmethod
    def _unique_preserve_order(items: list) -> list:
        out = []
        seen = set()
        for item in items:
            key = str(item)
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
        return out

    @staticmethod
    def _signature_detail_key(detail: Dict[str, Any]):
        return (
            str(detail.get('engine', '')).lower(),
            str(detail.get('id', '')).lower(),
            str(detail.get('severity', '')).lower(),
            str(detail.get('category', '')).lower(),
        )

    @staticmethod
    def _cache_key(sha: str, scan_type: str) -> str:
        if not sha:
            return ''
        return f'{sha}:{scan_type or "full"}'

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

            sig_engine = self.results.get('signature_engine', {})
            yara_error = sig_engine.get('yara_error')
            if yara_error and model_type != 'huggingface':
                msg = f'YARA disabled: {yara_error}'
                if msg not in self.results['errors']:
                    self.results['errors'].append(msg)

            sha = self.results.get('file_info', {}).get('sha256')
            cache_key = self._cache_key(sha, scan_type)
            cached = self._load_cache(cache_key)
            if cached:
                self.logger.info('Using cached scan result')
                cached['scan_id'] = self.results['scan_id']
                cached['timestamp'] = self.results['timestamp']
                cached['path'] = path
                cached['scan_type'] = scan_type
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

            self._merge_signature_findings_into_results()
            self.calculate_risk()

            if cache_key:
                self._save_cache(cache_key, self.results)

        except Exception as e:
            self.logger.exception('Scanning failed')
            self.results['errors'].append(f'Scanning failed: {e} | {traceback.format_exc()}')

        return self.results

    def scan_directory(self, directory: str, scan_type: str = 'full') -> Dict[str, Any]:
        dir_path = Path(directory)
        if not dir_path.exists() or not dir_path.is_dir():
            return {'error': f'Directory not found: {directory}'}
        
        supported_extensions = {'.pkl', '.pickle', '.pt', '.pth', '.bin', '.h5', '.keras', '.hdf5',
                               '.safetensors', '.onnx', '.pb', '.zip'}
        
        model_files = []
        for ext in supported_extensions:
            for candidate in dir_path.glob(f'**/*{ext}'):
                if ext == '.bin' and not self._is_probable_pytorch_bin(candidate):
                    continue
                model_files.append(candidate)
        
        if not model_files:
            return {
                'directory': str(directory),
                'total_files': 0,
                'scanned_files': 0,
                'results': [],
                'overall_risk_level': 'N/A',
                'overall_risk_score': 0.0,
                'summary': {
                    'critical_count': 0,
                    'high_count': 0,
                    'medium_count': 0,
                    'low_count': 0,
                    'safe_count': 0
                }
            }
        
        all_results = []
        risk_summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'SAFE': 0}
        total_warnings = 0
        total_errors = 0
        
        self.logger.info(f'Found {len(model_files)} model files in {directory}')
        
        for idx, model_file in enumerate(model_files, 1):
            try:
                self.logger.info(f'Scanning {idx}/{len(model_files)}: {model_file.name}')
                result = self.scan(str(model_file), scan_type)
                all_results.append(result)
                
                risk_level = result.get('risk_assessment', {}).get('level', 'UNKNOWN')
                if risk_level in risk_summary:
                    risk_summary[risk_level] += 1
                
                total_warnings += len(result.get('warnings', []))
                total_errors += len(result.get('errors', []))
            except Exception as e:
                self.logger.error(f'Failed to scan {model_file.name}: {e}')
                all_results.append({
                    'path': str(model_file),
                    'error': str(e),
                    'risk_assessment': {'level': 'ERROR', 'score': 0.0}
                })
        
        avg_risk_score = 0.0
        if all_results:
            valid_scores = [r.get('risk_assessment', {}).get('score', 0.0) for r in all_results 
                           if r.get('risk_assessment', {}).get('level') != 'ERROR']
            avg_risk_score = sum(valid_scores) / len(valid_scores) if valid_scores else 0.0
        
        if risk_summary['CRITICAL'] > 0:
            overall_level = 'CRITICAL'
        elif risk_summary['HIGH'] > 0:
            overall_level = 'HIGH'
        elif risk_summary['MEDIUM'] > 0:
            overall_level = 'MEDIUM'
        elif risk_summary['LOW'] > 0:
            overall_level = 'LOW'
        else:
            overall_level = 'SAFE'
        
        return {
            'directory': str(directory),
            'total_files': len(model_files),
            'scanned_files': len(all_results),
            'results': all_results,
            'overall_risk_level': overall_level,
            'overall_risk_score': round(avg_risk_score, 2),
            'summary': {
                'critical_count': risk_summary['CRITICAL'],
                'high_count': risk_summary['HIGH'],
                'medium_count': risk_summary['MEDIUM'],
                'low_count': risk_summary['LOW'],
                'safe_count': risk_summary['SAFE']
            },
            'statistics': {
                'total_warnings': total_warnings,
                'total_errors': total_errors,
                'scan_type': scan_type,
                'timestamp': datetime.now().isoformat()
            }
        }

    def detect_type(self, in_path: str) -> str:
        path = Path(in_path)
        if '/' in in_path and not path.exists():
            return 'huggingface'
        if not path.exists():
            raise FileNotFoundError(f'Model file not found: {in_path}')
        exts = path.suffix.lower()
        if exts == '.bin':
            return 'pytorch' if self._is_probable_pytorch_bin(path) else 'unknown'
        mapping = {
            '.pkl': 'pickle', '.pickle': 'pickle', '.pt': 'pytorch', '.pth': 'pytorch',
            '.h5': 'keras', '.keras': 'keras', '.hdf5': 'keras', '.safetensors': 'safetensors',
            '.onnx': 'onnx', '.pb': 'tensorflow', '.zip': 'zip_archive'
        }
        return mapping.get(exts, 'unknown')

    @staticmethod
    def _is_probable_pytorch_bin(path: Path) -> bool:
        name = path.name.lower()
        parts = [str(p).lower() for p in path.parts]
        if not name.endswith('.bin'):
            return False
        if any('openvino' in p for p in parts):
            return False
        if any(k in name for k in ['openvino', 'quantized', 'qint8', 'ggml', 'tokenizer']):
            return False
        if name in {'pytorch_model.bin', 'adapter_model.bin', 'model.bin'}:
            return True
        return 'pytorch' in name or 'adapter' in name

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
        out: Dict[str, Any] = {
            'quick_signatures': [],
            'quick_signature_details': [],
            'hf_meta': {},
            'cache_ttl_days': self.CACHE_TTL_DAYS,
        }
        out['quick_signatures'] = self.signature_scan(path)
        out['quick_signature_details'] = list(self._last_signature_details)
        out['signature_engine'] = self._signature_engine_status()
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
        details = []
        regex_patterns = [r'os\.system', r'subprocess', r'urlopen', r'reverse_shell', r'bind_shell', r'curl\s', r'wget\s']
        model_file = Path(model_path)
        if not model_file.exists() or not model_file.is_file():
            self._last_signature_details = []
            return findings
        try:
            with open(model_path, 'rb') as f:
                sample = f.read(self.MAX_SIGNATURE_SAMPLE_BYTES)
                try:
                    text = sample.decode('latin-1', errors='ignore')
                except Exception:
                    text = ''
                for p in regex_patterns:
                    if re.search(p, text, re.IGNORECASE):
                        findings.append(p)
                        details.append({
                            'engine': 'regex',
                            'id': p,
                            'severity': 'low',
                            'category': 'heuristic',
                            'description': 'Legacy static regex marker',
                        })

            if self._yara_rules is not None:
                try:
                    with warnings.catch_warnings():
                        warnings.filterwarnings('ignore', message='too many matches for string .*')
                        matches = self._yara_rules.match(filepath=model_path, timeout=self.YARA_MATCH_TIMEOUT)
                    for m in matches:
                        rule_id = str(m.rule)
                        meta = self._normalize_yara_meta(getattr(m, 'meta', {}) or {})
                        findings.append(f'yara:{rule_id}')
                        details.append({
                            'engine': 'yara',
                            'id': rule_id,
                            'severity': meta['severity'],
                            'category': meta['category'],
                            'description': meta['description'],
                        })
                except Exception as e:
                    self._yara_engine_error = f'yara runtime error: {e}'
                    if self.verb:
                        self.logger.debug(f'YARA runtime failed: {e}')
            if self.verb:
                try:
                    self.logger.debug('Signature scan', extra={'findings': findings, 'sample_len': len(sample)})
                except Exception:
                    self.logger.debug('Signature scan (debug)')
        except Exception as e:
            self.logger.debug(f'signature_scan failed: {e}')
        dedup_details = []
        details_seen = set()
        for detail in details:
            key = self._signature_detail_key(detail)
            if key in details_seen:
                continue
            details_seen.add(key)
            dedup_details.append(detail)
        self._last_signature_details = dedup_details
        return self._unique_preserve_order(findings)

    def _cache_dir_candidates(self):
        candidates = []

        # Optional explicit override for automation/tests.
        env_cache_dir = os.environ.get('LAS_CACHE_DIR')
        if env_cache_dir:
            candidates.append(Path(env_cache_dir))

        if os.name == 'nt':
            # Prefer a user-writable cache location on Windows.
            local_app_data = os.environ.get('LOCALAPPDATA') or os.environ.get('APPDATA')
            if local_app_data:
                candidates.append(Path(local_app_data) / 'LocalAIScanner' / 'cache')
        else:
            xdg_cache = os.environ.get('XDG_CACHE_HOME')
            if xdg_cache:
                candidates.append(Path(xdg_cache) / 'local-ai-scanner')
            candidates.append(Path.home() / '.cache' / 'local-ai-scanner')

        # Backward-compatible fallback for source-based runs.
        candidates.append(Path(__file__).parent / '.cache')
        # Last-resort fallback to temporary directory.
        candidates.append(Path(tempfile.gettempdir()) / 'local-ai-scanner-cache')

        deduped = []
        seen = set()
        for candidate in candidates:
            key = str(candidate.expanduser())
            if key in seen:
                continue
            seen.add(key)
            deduped.append(candidate)
        return deduped

    def _cache_path(self) -> Path:
        for cache_dir in self._cache_dir_candidates():
            try:
                cache_dir.mkdir(parents=True, exist_ok=True)
                # Validate we can write here.
                probe = cache_dir / '.write_probe'
                with open(probe, 'w', encoding='utf-8') as f:
                    f.write('ok')
                probe.unlink(missing_ok=True)
                return cache_dir / 'scans.json'
            except Exception as e:
                if self.verb:
                    self.logger.debug(f'Cache path unusable: {cache_dir} ({e})')

        # Last-resort fallback to temporary directory.
        tmp_cache = Path(tempfile.gettempdir()) / 'local-ai-scanner-cache'
        try:
            tmp_cache.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        return tmp_cache / 'scans.json'

    def _is_cache_entry_fresh(self, entry: Dict[str, Any], max_age_days: int = None) -> bool:
        if max_age_days is None:
            max_age_days = self.CACHE_TTL_DAYS
        if not isinstance(entry, dict):
            return False

        try:
            schema_version = int(entry.get('_cache_schema_version', 0))
        except Exception:
            return False
        engine_version = str(entry.get('_risk_engine_version', ''))
        if schema_version != self.CACHE_SCHEMA_VERSION or engine_version != self.RISK_ENGINE_VERSION:
            return False

        ts = entry.get('timestamp')
        if not ts:
            return False
        try:
            then = datetime.fromisoformat(str(ts))
        except Exception:
            return False
        return (datetime.now() - then).days <= max_age_days

    def cleanup_stale_cache(self, max_age_days: int = None) -> Dict[str, Any]:
        if max_age_days is None:
            max_age_days = self.CACHE_TTL_DAYS

        path = self._cache_path()
        summary = {
            'path': str(path),
            'total_entries': 0,
            'removed_entries': 0,
        }
        if not path.exists():
            return summary

        try:
            with open(path, 'r', encoding='utf-8') as f:
                cache = json.load(f)
        except Exception as e:
            self.logger.debug(f'Cache cleanup load failed: {e}')
            return summary

        if not isinstance(cache, dict):
            summary['removed_entries'] = 1
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump({}, f, ensure_ascii=False, indent=2)
            except Exception as e:
                self.logger.debug(f'Cache cleanup rewrite failed: {e}')
            return summary

        summary['total_entries'] = len(cache)
        fresh_cache = {}
        removed = 0

        for sha, entry in cache.items():
            if self._is_cache_entry_fresh(entry, max_age_days=max_age_days):
                fresh_cache[sha] = entry
            else:
                removed += 1

        if removed > 0:
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(fresh_cache, f, ensure_ascii=False, indent=2)
            except Exception as e:
                self.logger.debug(f'Cache cleanup save failed: {e}')
                return summary

        summary['removed_entries'] = removed
        if removed and self.verb:
            self.logger.debug('Removed stale cache entries', extra=summary)
        return summary

    def clear_cache(self) -> Dict[str, Any]:
        removed_files = 0
        removed_entries = 0

        for cache_dir in self._cache_dir_candidates():
            cache_file = cache_dir / 'scans.json'
            if not cache_file.exists():
                continue

            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    cached = json.load(f)
                if isinstance(cached, dict):
                    removed_entries += len(cached)
                else:
                    removed_entries += 1
            except Exception:
                pass

            try:
                cache_file.unlink()
                removed_files += 1
            except Exception as e:
                self.logger.debug(f'Cache clear failed for {cache_file}: {e}')

        return {
            'removed_files': removed_files,
            'removed_entries': removed_entries,
        }

    def _load_cache(self, cache_key: str, max_age_days: int = None):
        if max_age_days is None:
            max_age_days = self.CACHE_TTL_DAYS
        if not cache_key:
            return None
        path = self._cache_path()
        try:
            if not path.exists():
                if self.verb:
                    self.logger.debug(f'Cache file not found: {path}')
                return None
            with open(path, 'r', encoding='utf-8') as f:
                cache = json.load(f)
            entry = cache.get(cache_key)
            if not entry:
                if self.verb:
                    self.logger.debug('Cache miss', extra={'cache_key': cache_key})
                return None
            if not self._is_cache_entry_fresh(entry, max_age_days=max_age_days):
                if self.verb:
                    self.logger.debug(
                        'Cache entry expired or incompatible',
                        extra={'cache_key': cache_key, 'max_age_days': max_age_days}
                    )
                return None
            return entry
        except Exception as e:
            self.logger.debug(f'Cache load failed: {e}')
            return None

    def _save_cache(self, cache_key: str, results: Dict[str, Any]):
        if not cache_key:
            return
        path = self._cache_path()
        try:
            cache = {}
            if path.exists():
                with open(path, 'r', encoding='utf-8') as f:
                    cache = json.load(f)
            to_store = {k: v for k, v in results.items() if k not in ('pytorch_analysis_raw',)}
            to_store['_cache_schema_version'] = self.CACHE_SCHEMA_VERSION
            to_store['_risk_engine_version'] = self.RISK_ENGINE_VERSION
            cache[cache_key] = to_store
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(cache, f, ensure_ascii=False, indent=2)
            if self.verb:
                self.logger.debug('Saved cache entry', extra={'cache_key': cache_key, 'path': str(path)})
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

    def _warnings_from_signature_details(self, details: list) -> list:
        out = []
        if not details:
            return out
        for detail in details:
            if str(detail.get('engine', '')).lower() != 'yara':
                continue
            rule_id = str(detail.get('id', 'unknown'))
            severity = str(detail.get('severity', 'medium')).lower()
            category = str(detail.get('category', 'generic')).lower()
            if severity not in {'medium', 'high', 'critical'}:
                continue
            out.append(f'YARA {severity} signature: {rule_id} ({category})')
        return self._unique_preserve_order(out)

    def _merge_signature_findings_into_results(self):
        issues = list(self.results.get('security_issues', []) or [])
        for issue in self._issues_from_quick_signatures(
            self.results.get('quick_signatures', []),
            self.results.get('quick_signature_details', [])
        ):
            if issue not in issues:
                issues.append(issue)
        self.results['security_issues'] = issues

        warnings_out = list(self.results.get('warnings', []) or [])
        for warning in self._warnings_from_signature_details(self.results.get('quick_signature_details', [])):
            if warning not in warnings_out:
                warnings_out.append(warning)
        self.results['warnings'] = warnings_out

    def _issues_from_quick_signatures(self, signatures: list, details: list = None) -> list:
        out = []
        if not signatures:
            return out
        detail_map = {}
        for detail in details or []:
            if str(detail.get('engine', '')).lower() != 'yara':
                continue
            rule_id = str(detail.get('id', '')).lower()
            if rule_id and rule_id not in detail_map:
                detail_map[rule_id] = detail
        for sig in signatures:
            raw_sig = str(sig)
            s = raw_sig.lower()
            if s.startswith('yara:'):
                rule_id = raw_sig.split(':', 1)[1] if ':' in raw_sig else raw_sig
                meta = detail_map.get(rule_id.lower(), {})
                severity = str(meta.get('severity', 'unknown')).upper()
                category = str(meta.get('category', 'generic')).lower()
                out.append(f'YARA match [{severity}/{category}]: {rule_id}')
                if str(meta.get('severity', 'medium')).lower() in {'high', 'critical'}:
                    out.append(f'Known trojan signature: yara:{rule_id} ({severity})')
                continue
            if 'reverse_shell' in s or 'bind_shell' in s or 'meterpreter' in s or 'beacon' in s:
                out.append(f'Known trojan signature: {raw_sig}')
                continue
            if any(k in s for k in ['os\\.system', 'subprocess', 'eval', 'exec']):
                out.append(f'Dangerous system call marker: {raw_sig}')
                continue
            if any(k in s for k in ['http', 'urlopen', 'curl', 'wget', 'socket', 'connect']):
                out.append(f'Network operations marker: {raw_sig}')
        return self._unique_preserve_order(out)

    @staticmethod
    def _looks_dangerous_code_marker(text: str) -> bool:
        if not text:
            return False
        s = str(text).lower()
        patterns = [
            r'\bos\.system\b',
            r'\bsubprocess\b',
            r'\b(eval|exec|compile)\s*\(',
            r'\b__import__\s*\(',
            r'\bimport\s+os\b',
            r'\bopen\s*\(',
            r'\burlopen\s*\(',
            r'\bsocket\b',
            r'\brequests?\b',
        ]
        return any(re.search(p, s) for p in patterns)

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
                if self._looks_dangerous_code_marker(str(arg)):
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
            issues.append('ZIP archive - inspect contents')
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
        if model_type == 'pickle':
            try:
                with open(model_path, 'rb') as f:
                    data = f.read()
                for op in pickletools.genops(data):
                    arg_str = str(op[1])
                    if self._looks_dangerous_code_marker(arg_str):
                        issues.append(f'Dangerous system call: {arg_str}')
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
                    elif model_type in ('safetensors', 'onnx'):
                        issues.append(f'Potential marker string in safe-format artifact: {sig}')
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
                total_tensors = meta.get('total_tensors', 0)

                shadow_logic_score = 0.0
                bias_anomalies = []
                weight_anomalies = []
                entropy_anomalies = []
                dangerous_key_markers = []

                for key, stats in tensor_stats.items():
                    key_lower = str(key).lower()
                    param_type = stats.get('param_type', 'weight')
                    size = int(stats.get('size', 0) or 0)
                    unique_ratio = float(stats.get('unique_ratio', 1.0) or 1.0)
                    kurtosis_val = float(stats.get('kurtosis', 0.0) or 0.0)
                    skewness_val = abs(float(stats.get('skewness', 0.0) or 0.0))
                    entropy_val = float(stats.get('entropy', 0.0) or 0.0)
                    l2_norm = float(stats.get('l2_norm', 0.0) or 0.0)
                    mean_val = abs(float(stats.get('mean', 0.0) or 0.0))
                    sparsity = float(stats.get('sparsity', 0.0) or 0.0)

                    if any(k in key_lower for k in ['os.system', 'subprocess', 'eval', 'exec', '__import__']):
                        dangerous_key_markers.append(f'{key}: system-call marker in tensor name')
                        shadow_logic_score += 0.35
                    elif any(k in key_lower for k in ['urlopen', 'socket', 'http', 'https', 'curl', 'wget', 'connect']):
                        dangerous_key_markers.append(f'{key}: network marker in tensor name')
                        shadow_logic_score += 0.25

                    if unique_ratio < 0.02:
                        weight_anomalies.append(f'{key}: low unique ratio {unique_ratio:.3f}')
                        shadow_logic_score += 0.2
                    if kurtosis_val > 80:
                        weight_anomalies.append(f'{key}: multimodal (kurtosis={kurtosis_val:.1f})')
                        shadow_logic_score += 0.35
                    if skewness_val > 4:
                        weight_anomalies.append(f'{key}: asymmetric (skew={skewness_val:.2f})')
                        shadow_logic_score += 0.2

                    if entropy_val > 6.0:
                        entropy_anomalies.append(f'{key}: high entropy={entropy_val:.2f}')
                        shadow_logic_score += 0.15
                    elif entropy_val < 0.05 and size > 1000:
                        entropy_anomalies.append(f'{key}: low entropy={entropy_val:.3f}')
                        shadow_logic_score += 0.2

                    if param_type == 'bias' and (kurtosis_val > 60 or mean_val > 8 or (unique_ratio < 0.005 and l2_norm > 200)):
                        bias_anomalies.append(
                            f'{key}: bias anomaly (k={kurtosis_val:.1f}, mean={mean_val:.2f}, sparsity={sparsity:.2f})'
                        )
                        shadow_logic_score += 0.3

                    if l2_norm > 5000 and unique_ratio < 0.005:
                        weight_anomalies.append(f'{key}: concentrated high energy (l2={l2_norm:.1f}, unique={unique_ratio:.4f})')
                        shadow_logic_score += 0.2

                if bias_anomalies:
                    backdoor_checks['suspicious_patterns'].append(f'Anomalous biases detected: {len(bias_anomalies)} layers')
                    for anomaly in bias_anomalies[:3]:
                        backdoor_checks['suspicious_patterns'].append(f'  {anomaly}')

                if weight_anomalies and len(weight_anomalies) <= 3:
                    for anomaly in weight_anomalies:
                        backdoor_checks['suspicious_patterns'].append(f'  {anomaly}')
                elif weight_anomalies:
                    backdoor_checks['suspicious_patterns'].append(f'Multiple weight anomalies: {len(weight_anomalies)} parameters')

                if entropy_anomalies:
                    backdoor_checks['suspicious_patterns'].append(f'Entropy anomalies detected in {len(entropy_anomalies)} tensors')

                if dangerous_key_markers:
                    backdoor_checks['suspicious_patterns'].append(f'Dangerous marker-like tensor names: {len(dangerous_key_markers)}')
                    for marker in dangerous_key_markers[:3]:
                        backdoor_checks['suspicious_patterns'].append(f'  {marker}')

                if shadow_logic_score > 1.2:
                    backdoor_checks['suspicious_patterns'].append(
                        f'Shadow logic score: {shadow_logic_score:.2f} (analyzed {total_tensors} tensors)'
                    )
                    backdoor_checks['recommendations'].append('Perform behavioral testing with adversarial inputs')

            elif model_type == 'keras' and HAS_TENSORFLOW:
                meta = self._run_inspector('keras', model_path)
                if meta and meta.get('layers'):
                    shadow_logic_score = 0.0
                    total_layers = len(meta.get('layers', []))
                    suspicious_layers = []

                    for layer_idx, layer in enumerate(meta.get('layers', [])):
                        weights = layer.get('weights', [])
                        layer_name = layer.get('name', f'Layer_{layer_idx}')

                        for w in weights:
                            weight_type = w.get('type', 'weight')
                            weight_stats = w.get('stats', {})
                            shape = w.get('shape', [])

                            if not weight_stats:
                                continue

                            kurt = float(weight_stats.get('kurtosis', 0.0) or 0.0)
                            skew = abs(float(weight_stats.get('skewness', 0.0) or 0.0))
                            entropy_val = float(weight_stats.get('entropy', 0.0) or 0.0)
                            l2_norm = float(weight_stats.get('l2_norm', 0.0) or 0.0)
                            sparsity = float(weight_stats.get('sparsity', 0.0) or 0.0)
                            abs_max = max(
                                abs(float(weight_stats.get('max', 0.0) or 0.0)),
                                abs(float(weight_stats.get('min', 0.0) or 0.0))
                            )

                            layer_issues = []
                            if weight_type == 'bias' and (kurt > 5 or skew > 2 or abs_max > 10):
                                layer_issues.append('anomalous_bias')
                                shadow_logic_score += 0.3
                            if kurt > 8:
                                layer_issues.append(f'multimodal(k={kurt:.1f})')
                                shadow_logic_score += 0.35
                            if entropy_val > 5:
                                layer_issues.append(f'high_entropy(h={entropy_val:.1f})')
                                shadow_logic_score += 0.2
                            elif entropy_val > 4.5 and abs_max > 20:
                                layer_issues.append(f'high_entropy_payload(h={entropy_val:.1f}, max={abs_max:.1f})')
                                shadow_logic_score += 0.25
                            if len(shape) > 1 and shape[-1] > 5000:
                                layer_issues.append(f'huge_output({shape[-1]})')
                                shadow_logic_score += 0.2
                            if l2_norm > 2500 and sparsity > 0.9:
                                layer_issues.append(f'concentrated_energy(l2={l2_norm:.1f}, sparsity={sparsity:.2f})')
                                shadow_logic_score += 0.15

                            if layer_issues:
                                suspicious_layers.append((layer_name, weight_type, layer_issues))

                    if suspicious_layers:
                        backdoor_checks['suspicious_patterns'].append(
                            f'Suspicious patterns in {len(suspicious_layers)} weight tensors:'
                        )
                        for layer_name, w_type, issues in suspicious_layers[:6]:
                            backdoor_checks['suspicious_patterns'].append(
                                f'  {layer_name}[{w_type}]: {", ".join(issues)}'
                            )

                    if shadow_logic_score >= 0.25:
                        backdoor_checks['suspicious_patterns'].append(
                            f'Shadow logic score: {shadow_logic_score:.2f} (analyzed {total_layers} layers)'
                        )
                        backdoor_checks['recommendations'].append('Verify predictions on test data and adversarial samples')

        except Exception as e:
            self.logger.debug(f'Trigger pattern analysis failed: {e}')

    def check_anomalous_behavior(self, model_path: str, model_type: str, backdoor_checks: dict):
        backdoor_checks['performed_checks'].append('anomalous_behavior')
        if model_type in ['keras', 'pytorch'] and self.is_computer_vision_model(model_path, model_type):
            backdoor_checks['suspicious_patterns'].append('CV model: test with patch triggers')
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
        security_contrib = min(
            len(security) * float(w.get('security_count', 1.2)),
            float(caps.get('security', 8.0))
        )

        back = self.results.get('backdoor_analysis', {})
        susp_all = back.get('suspicious_patterns', [])
        # Ignore indented detail lines when scoring risk to reduce false positives.
        susp = [s for s in susp_all if not str(s).startswith('  ')]
        backdoor_contrib = min(
            len(susp) * float(w.get('backdoor_count', 1.4)),
            float(caps.get('backdoor', 8.0))
        )

        critical_raw = 0.0
        network_ops_count = 0
        system_calls_count = 0
        trojan_sigs_count = 0
        shadow_pattern_count = 0
        has_shadow_score = False
        has_marker_tensor_names = False
        yara_critical_count = 0
        yara_high_count = 0
        yara_medium_count = 0

        for msg in self.results.get('warnings', []):
            msg_lower = msg.lower()
            if 'yara critical signature' in msg_lower:
                critical_raw += float(w.get('yara_critical', 2.2))
                yara_critical_count += 1
            elif 'yara high signature' in msg_lower:
                critical_raw += float(w.get('yara_high', 1.6))
                yara_high_count += 1
            elif 'yara medium signature' in msg_lower:
                critical_raw += float(w.get('yara_medium', 0.8))
                yara_medium_count += 1
            elif 'known trojan signature' in msg_lower or any(k in msg_lower for k in ['reverse_shell', 'beacon', 'meterpreter']):
                critical_raw += float(w.get('warning_critical', 2.0))
                trojan_sigs_count += 1
            elif any(k in msg_lower for k in ['network operations', 'http', 'socket', 'request', 'connect', 'urlopen']):
                critical_raw += float(w.get('network_ops', 1.5))
                network_ops_count += 1
            elif any(k in msg_lower for k in ['dangerous system call', 'dangerous call in pickle', 'os.', 'subprocess', 'eval', 'exec', 'import os']):
                critical_raw += float(w.get('system_calls', 1.8))
                system_calls_count += 1
            elif 'shadow logic score' in msg_lower:
                critical_raw += float(w.get('shadow_pattern', 0.5))
                shadow_pattern_count += 1
                has_shadow_score = True
            if 'dangerous marker-like tensor names' in msg_lower:
                has_marker_tensor_names = True

        for issue in self.results.get('security_issues', []):
            issue_lower = issue.lower()
            if 'known trojan' in issue_lower:
                critical_raw += float(w.get('warning_critical', 2.0))
                trojan_sigs_count += 1
            elif any(k in issue_lower for k in ['network operations', 'network operations marker']):
                if network_ops_count == 0:
                    critical_raw += float(w.get('network_ops', 1.5))
                    network_ops_count += 1
            elif 'dangerous system call' in issue_lower:
                if system_calls_count < len(security):
                    critical_raw += float(w.get('system_calls', 1.8))
                    system_calls_count += 1
            elif 'dangerous system call marker' in issue_lower:
                critical_raw += float(w.get('system_calls', 1.8))
                system_calls_count += 1

        critical_contrib = min(critical_raw, float(caps.get('critical', 8.0)))

        raw_score = format_contrib + security_contrib + backdoor_contrib + critical_contrib

        normalize_to = float(self.risk_config.get('normalize_to', 10.0))
        effective_max = float(self.risk_config.get('effective_max_raw', 16.0))
        if effective_max <= 0:
            normalized = 0.0
        else:
            normalized = round(min(raw_score, effective_max) / effective_max * normalize_to, 2)

        if normalized >= (0.85 * normalize_to):
            level = 'CRITICAL'
        elif normalized >= (0.60 * normalize_to):
            level = 'HIGH'
        elif normalized >= (0.35 * normalize_to):
            level = 'MEDIUM'
        else:
            level = 'LOW'

        severity = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}

        # Rule-based floor for explicit high-confidence indicators.
        if trojan_sigs_count >= 1 and (system_calls_count >= 1 or network_ops_count >= 1):
            if severity[level] < severity['HIGH']:
                level = 'HIGH'
        elif trojan_sigs_count >= 1 and severity[level] < severity['HIGH']:
            level = 'HIGH'

        if has_shadow_score and len(susp) >= 2 and severity[level] < severity['MEDIUM']:
            level = 'MEDIUM'

        if has_marker_tensor_names and (system_calls_count >= 1 or trojan_sigs_count >= 1):
            if severity[level] < severity['HIGH']:
                level = 'HIGH'

        if system_calls_count >= 3 and trojan_sigs_count >= 1 and severity[level] < severity['CRITICAL']:
            level = 'CRITICAL'
        if yara_critical_count >= 1 and severity[level] < severity['HIGH']:
            level = 'HIGH'
        if yara_critical_count >= 1 and (system_calls_count >= 1 or network_ops_count >= 1) and severity[level] < severity['CRITICAL']:
            level = 'CRITICAL'
        if yara_high_count >= 2 and severity[level] < severity['HIGH']:
            level = 'HIGH'

        # Light false-positive damping: downgrade MEDIUM only for low-signal cases.
        low_signal_medium = (
            level == 'MEDIUM'
            and trojan_sigs_count == 0
            and yara_critical_count == 0
            and yara_high_count == 0
            and system_calls_count == 0
            and network_ops_count <= 1
            and len(security) <= 2
            and len(susp) <= 1
            and errors_count == 0
        )
        if low_signal_medium:
            level = 'LOW'

        self.results['risk_assessment'] = {
            'raw_score': round(raw_score, 3),
            'score': normalized,
            'scale': normalize_to,
            'max_possible': round(effective_max, 3),
            'level': level,
            'warnings_count': warnings_count,
            'errors_count': errors_count,
            'security_issues_count': len(security),
            'backdoor_suspicions_count': len(susp),
            'breakdown': {
                'format_threat': round(format_contrib, 3),
                'security_threats': round(security_contrib, 3),
                'backdoor_patterns': round(backdoor_contrib, 3),
                'critical_threats': round(critical_contrib, 3),
                'trojan_signatures': trojan_sigs_count,
                'network_operations': network_ops_count,
                'system_calls': system_calls_count,
                'shadow_patterns': shadow_pattern_count,
                'yara_critical': yara_critical_count,
                'yara_high': yara_high_count,
                'yara_medium': yara_medium_count
            }
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
