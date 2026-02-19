import json
from typing import Dict,Any
from datetime import datetime


class Outputer:
    @staticmethod
    def directory_scan_console(results: Dict[str,Any]) -> str:
        output = []
        if 'directory' in results:
            output.append("=" * 80)
            output.append("LOCAL AI SCANNER - DIRECTORY SCANNING RESULTS")
            output.append("=" * 80)
            output.append(f"Directory: {results.get('directory', 'N/A')}")
            output.append(f"Total files found: {results.get('total_files', 0)}")
            output.append(f"Scanned: {results.get('scanned_files', 0)}")
            output.append(f"Scan time: {results.get('statistics', {}).get('timestamp', 'N/A')}")
            output.append("-" * 80)
            
            output.append("\nSCAN RESULTS BY FILE:")
            output.append("-" * 80)
            
            risk_colors = {
                'CRITICAL': '[CRITICAL]',
                'HIGH': '[HIGH]',
                'MEDIUM': '[MEDIUM]',
                'LOW': '[LOW]',
                'SAFE': '[SAFE]',
                'ERROR': '[ERROR]'
            }
            
            for idx, file_result in enumerate(results.get('results', []), 1):
                path = file_result.get('path', 'Unknown').replace('\\', '/')
                if file_result.get('error'):
                    risk_level = 'ERROR'
                    risk_score = 'N/A'
                    status = f"{risk_colors.get(risk_level, risk_level)}"
                    warnings_count = 0
                    threats_count = 0
                else:
                    risk_level = file_result.get('risk_assessment', {}).get('level', 'UNKNOWN')
                    risk_score = file_result.get('risk_assessment', {}).get('score', 0)
                    status = f"{risk_colors.get(risk_level, risk_level)}"
                    warnings_count = len(file_result.get('warnings', []))
                    threats_count = len(file_result.get('security_issues', []))
                
                output.append(f"\n[{idx}] {path}")
                output.append(f"     Risk: {status} ({risk_score}/10)" if risk_score != 'N/A' else f"     Status: {status}")
                
                if warnings_count > 0 or threats_count > 0:
                    output.append(f"     Warnings: {warnings_count} | Threats found: {threats_count}")
                
                if file_result.get('error'):
                    output.append(f"     ERROR: {file_result.get('error', 'Unknown error')}")
            
            output.append("\n" + "=" * 80)
            summary = results.get('summary', {})
            overall = results.get('overall_risk_level', 'N/A')
            score = results.get('overall_risk_score', 0)
            
            output.append("\nSUMMARY STATISTICS:")
            output.append(f"  CRITICAL: {summary.get('critical_count', 0)}")
            output.append(f"  HIGH: {summary.get('high_count', 0)}")
            output.append(f"  MEDIUM: {summary.get('medium_count', 0)}")
            output.append(f"  LOW: {summary.get('low_count', 0)}")
            output.append(f"  SAFE: {summary.get('safe_count', 0)}")
            output.append("\n" + "="*80)
            output.append(f"OVERALL RISK: {overall} ({score}/10)")
            output.append("=" * 80)
            
            stats = results.get('statistics', {})
            output.append(f"\nTotal warnings: {stats.get('total_warnings', 0)}")
            output.append(f"Total errors: {stats.get('total_errors', 0)}")
            
            return "\n".join(output)
        else:
            return "Invalid results format for directory scan"
    
    @staticmethod
    def summary_format(results: Dict[str,Any]) -> str:
        output = []
        if 'directory' in results:
            output.append("=" * 70)
            output.append("LOCAL AI SCANNER - DIRECTORY SCANNING SUMMARY")
            output.append("=" * 70)
            output.append(f"Directory: {results.get('directory', 'N/A')}")
            output.append(f"Total files: {results.get('total_files', 0)}")
            output.append(f"Scanned: {results.get('scanned_files', 0)}")
            output.append(f"Time: {results.get('statistics', {}).get('timestamp', 'N/A')}")
            output.append("-" * 70)
            
            output.append("\nRESULTS:")
            summary = results.get('summary', {})
            output.append(f"  CRITICAL: {summary.get('critical_count', 0)}")
            output.append(f"  HIGH: {summary.get('high_count', 0)}")
            output.append(f"  MEDIUM: {summary.get('medium_count', 0)}")
            output.append(f"  LOW: {summary.get('low_count', 0)}")
            output.append(f"  SAFE: {summary.get('safe_count', 0)}")
            
            output.append("\n" + "=" * 70)
            overall = results.get('overall_risk_level', 'N/A')
            score = results.get('overall_risk_score', 0)
            output.append(f"OVERALL RISK: {overall} ({score}/10)")
            output.append("=" * 70)
            
            stats = results.get('statistics', {})
            output.append(f"\nOverall warnings: {stats.get('total_warnings', 0)}")
            output.append(f"Overall errors: {stats.get('total_errors', 0)}")
            
            return "\n".join(output)
        else:
            return "Invalid results format for summary"

    @staticmethod
    def text_format(results: Dict[str,Any]) -> str:
        if 'directory' in results:
            return Outputer._text_format_directory(results)
        else:
            return Outputer._text_format_single(results)
    
    @staticmethod
    def _text_format_single(results: Dict[str,Any]) -> str:
        output = []
        output.append("=" * 70)
        output.append("LOCAL AI SCANNER - ADVANCED SECURITY ANALYSIS")
        output.append("="*70)
        output.append(f"Model: {results.get('path', 'N/A')}")
        output.append(f"Model type: {results.get('model_type', 'N/A')}")
        output.append(f"Scan type: {results.get('scan_type', 'N/A')}")
        output.append(f"Scan ID: {results.get('scan_id', 'N/A')}")
        output.append(f"Timestamp: {results.get('timestamp', 'N/A')}")
        output.append("-" * 70)

        file_info = results.get('file_info', {})
        if file_info:
            output.append("FILE INFORMATION:")
            if 'file_size_mb' in file_info:
                output.append(f"  Size: {file_info.get('file_size_mb', 'N/A')} MB")
            if 'sha256' in file_info:
                output.append(f"  SHA256: {file_info.get('sha256', 'N/A')[:32]}...")

        risk = results.get('risk_assessment', {})
        risk_level = risk.get('level', 'N/A')
        risk_score = risk.get('score', 'N/A')
        output.append("\n" + "="*70)
        output.append(f"RISK ASSESSMENT: {risk_level} ({risk_score}/10)")
        output.append("="*70)

        warnings = results.get('warnings', [])
        if warnings:
            output.append(f"\nWARNINGS ({len(warnings)}):")
            for i, warning in enumerate(warnings[:10], 1):
                output.append(f"  {i}. {warning[:80]}")
            if len(warnings) > 10:
                output.append(f"  ... and {len(warnings) - 10} more")

        errors = results.get('errors', [])
        if errors:
            output.append(f"\nERRORS ({len(errors)}):")
            for i, error in enumerate(errors[:5], 1):
                output.append(f"  {i}. {error[:80]}")

        security_issues = results.get('security_issues', [])
        if security_issues:
            output.append(f"\nSECURITY THREATS ({len(security_issues)}):")
            for i, issue in enumerate(security_issues[:10], 1):
                output.append(f"  {i}. {issue[:70]}")
            if len(security_issues) > 10:
                output.append(f"  ... and {len(security_issues) - 10} more")

        backdoor_analysis = results.get('backdoor_analysis', {})
        if backdoor_analysis:
            output.append(f"\nBACKDOOR ANALYSIS:")
            output.append(f"  Checks performed: {', '.join(backdoor_analysis.get('performed_checks', []))}")  
            patterns = backdoor_analysis.get('suspicious_patterns', [])
            if patterns:
                output.append(f"  SUSPICIOUS PATTERNS ({len(patterns)}):")
                for i, pattern in enumerate(patterns[:8], 1):
                    output.append(f"    {i}. {pattern}")
                if len(patterns) > 8:
                    output.append(f"    ... and {len(patterns) - 8} more")
            else:
                output.append("  No suspicious patterns detected")

        recommendations = results.get('recommendations', [])
        if recommendations:
            output.append(f"\nRECOMMENDATIONS ({len(recommendations)}):")
            for i, rec in enumerate(recommendations[:5], 1):
                output.append(f"  {i}. {rec}")

        if risk.get('breakdown'):
            output.append(f"\nSCORE BREAKDOWN:")
            breakdown = risk['breakdown']
            label_map = {
                'format_threat': 'Format Risk',
                'security_threats': 'Security Threats',
                'backdoor_patterns': 'Backdoor Patterns',
                'critical_threats': 'Critical Threats',
                'trojan_signatures': 'Trojan Signatures',
                'network_operations': 'Network Operations',
                'system_calls': 'Dangerous System Calls'
            }
            for key, value in breakdown.items():
                if key in label_map:
                    label = label_map[key]
                    if isinstance(value, float):
                        output.append(f"  {label}: {value:.2f}")
                    else:
                        output.append(f"  {label}: {value}")
            
            if 'raw_score' in risk:
                output.append(f"\nFinal score: {risk['raw_score']} out of {risk.get('max_possible', 10.0)} (normalized: {risk['score']}/10)")

        output.append("=" * 70)
        return "\n".join(output)
    
    @staticmethod
    def _text_format_directory(results: Dict[str,Any]) -> str:
        output = []
        output.append("=" * 80)
        output.append("LOCAL AI SCANNER - FULL DIRECTORY SCAN REPORT")
        output.append("=" * 80)
        output.append(f"Directory: {results.get('directory', 'N/A')}")
        output.append(f"Total files: {results.get('total_files', 0)}")
        output.append(f"Scanned: {results.get('scanned_files', 0)}")
        output.append(f"Scan time: {results.get('statistics', {}).get('timestamp', 'N/A')}")
        output.append("-" * 80)
        
        summary = results.get('summary', {})
        output.append("\nРЕЗУЛЬТАТЫ:")
        output.append(f"  КРИТИЧЕСКИХ: {summary.get('critical_count', 0)}")
        output.append(f"  ВЫСОКИХ: {summary.get('high_count', 0)}")
        output.append(f"  СРЕДНИХ: {summary.get('medium_count', 0)}")
        output.append(f"  НИЗКИХ: {summary.get('low_count', 0)}")
        output.append(f"  БЕЗОПАСНЫХ: {summary.get('safe_count', 0)}")
        
        stats = results.get('statistics', {})
        output.append(f"\nОбщие предупреждения: {stats.get('total_warnings', 0)}")
        output.append(f"Общие ошибки: {stats.get('total_errors', 0)}")
        
        output.append("\n" + "=" * 80)
        overall = results.get('overall_risk_level', 'N/A')
        score = results.get('overall_risk_score', 0)
        output.append(f"OVERALL RISK: {overall} ({score}/10)")
        output.append("=" * 80)
        
        output.append("\nDETAILED ANALYSIS BY FILE:")
        output.append("-" * 80)
        
        for idx, file_result in enumerate(results.get('results', []), 1):
            output.append(f"\n[{idx}] {file_result.get('path', 'Unknown')}")
            
            if file_result.get('error'):
                output.append(f"    ERROR: {file_result.get('error', 'Unknown error')}")
                continue
            
            risk_level = file_result.get('risk_assessment', {}).get('level', 'UNKNOWN')
            risk_score = file_result.get('risk_assessment', {}).get('score', 0)
            output.append(f"    Risk level: {risk_level} ({risk_score}/10)")
            
            warnings = file_result.get('warnings', [])
            if warnings:
                output.append(f"\n    WARNINGS ({len(warnings)}):")
                for i, warning in enumerate(warnings, 1):
                    output.append(f"      {i}. {warning}")
            
            security_issues = file_result.get('security_issues', [])
            if security_issues:
                output.append(f"\n    THREATS FOUND ({len(security_issues)}):")
                for i, issue in enumerate(security_issues, 1):
                    output.append(f"      {i}. {issue}")
            
            backdoor = file_result.get('backdoor_analysis', {})
            patterns = backdoor.get('suspicious_patterns', [])
            if patterns:
                output.append(f"\n    SUSPICIOUS PATTERNS ({len(patterns)}):")
                for i, pattern in enumerate(patterns, 1):
                    output.append(f"      {i}. {pattern}")
            
            recommendations = file_result.get('recommendations', [])
            if recommendations:
                output.append(f"\n    RECOMMENDATIONS ({len(recommendations)}):")
                for i, rec in enumerate(recommendations, 1):
                    output.append(f"      {i}. {rec}")
        
        output.append("\n" + "=" * 80)
        return "\n".join(output)
    
    @staticmethod
    def json_format(results: Dict[str, Any]) -> str:
        return json.dumps(results, indent=2, ensure_ascii=False)

    @staticmethod
    def csv_format(results: Dict[str,Any]) -> str:
        import io
        import csv

        if 'directory' in results:
            return Outputer._csv_format_directory(results)
        else:
            return Outputer._csv_format_single(results)
    
    @staticmethod
    def _csv_format_single(results: Dict[str,Any]) -> str:
        import io
        import csv
        
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Field', 'Value'])

        writer.writerow(['model_path', results.get('path', '')])
        writer.writerow(['model_type', results.get('model_type', '')])
        writer.writerow(['scan_type', results.get('scan_type', '')])
        writer.writerow(['scan_id', results.get('scan_id', '')])
        writer.writerow(['timestamp', results.get('timestamp', '')])

        file_info = results.get('file_info', {})
        writer.writerow(['file_size_mb', file_info.get('file_size_mb', '')])
        writer.writerow(['sha256', file_info.get('sha256', '')])

        risk = results.get('risk_assessment', {})
        writer.writerow(['risk_level', risk.get('level', '')])
        writer.writerow(['risk_score', risk.get('score', '')])
        writer.writerow(['risk_raw', risk.get('raw_score', '')])
        writer.writerow(['risk_max_possible', risk.get('max_possible', '')])

        breakdown = risk.get('breakdown', {})
        for key in ['format_threat', 'security_threats', 'backdoor_patterns', 'critical_threats', 
                    'trojan_signatures', 'network_operations', 'system_calls']:
            writer.writerow([key, breakdown.get(key, '')])

        writer.writerow(['warnings_count', len(results.get('warnings', []))])
        writer.writerow(['errors_count', len(results.get('errors', []))])
        writer.writerow(['security_issues_count', len(results.get('security_issues', []))])
        backdoor = results.get('backdoor_analysis', {})
        writer.writerow(['backdoor_patterns_count', len(backdoor.get('suspicious_patterns', []))])
        writer.writerow(['recommendations_count', len(results.get('recommendations', []))])
        
        return output.getvalue()
    
    @staticmethod
    def _csv_format_directory(results: Dict[str,Any]) -> str:
        import io
        import csv
        
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['File Index', 'File Path', 'Risk Level', 'Risk Score', 'Warnings', 'Security Issues', 'Errors'])

        for idx, file_result in enumerate(results.get('results', []), 1):
            path = file_result.get('path', 'Unknown')
            if file_result.get('error'):
                writer.writerow([idx, path, 'ERROR', '', '', '', file_result.get('error', '')])
            else:
                risk_level = file_result.get('risk_assessment', {}).get('level', 'UNKNOWN')
                risk_score = file_result.get('risk_assessment', {}).get('score', 0)
                warnings_count = len(file_result.get('warnings', []))
                security_count = len(file_result.get('security_issues', []))
                errors_count = len(file_result.get('errors', []))
                writer.writerow([idx, path, risk_level, risk_score, warnings_count, security_count, errors_count])
        
        return output.getvalue()
    
    @staticmethod
    def html_format(results: Dict[str, Any]) -> str:
        """Return results as HTML report"""
        risk = results.get('risk_assessment', {})
        level = risk.get('level', 'UNKNOWN')
        score = risk.get('score', 0)
        

        color_map = {'CRITICAL': '#d32f2f', 'HIGH': '#f57c00', 'MEDIUM': '#fbc02d', 'LOW': '#388e3c'}
        color = color_map.get(level, '#757575')
        
        html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LOCAL AI SCANNER - {level}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        header {{ background: {color}; color: white; padding: 30px; border-radius: 8px 8px 0 0; }}
        header h1 {{ font-size: 28px; margin-bottom: 10px; }}
        header p {{ font-size: 14px; opacity: 0.9; }}
        .score-box {{ display: inline-block; background: rgba(255,255,255,0.2); padding: 10px 20px; border-radius: 4px; margin-top: 15px; font-size: 16px; }}
        .content {{ padding: 30px; }}
        .row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin-bottom: 30px; }}
        .section {{ margin-bottom: 30px; }}
        .section h2 {{ font-size: 18px; color: #333; margin-bottom: 15px; border-bottom: 2px solid {color}; padding-bottom: 10px; }}
        .info-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; }}
        .info-item {{ background: #f9f9f9; padding: 12px; border-left: 3px solid {color}; }}
        .info-item label {{ font-weight: 600; font-size: 12px; color: #666; text-transform: uppercase; }}
        .info-item value {{ display: block; font-size: 16px; color: #333; margin-top: 5px; }}
        .alert {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin-bottom: 10px; border-radius: 4px; }}
        .alert.critical {{ background: #f8d7da; border-left-color: #dc3545; }}
        .alert.high {{ background: #fff3cd; border-left-color: #ffc107; }}
        .alert.medium {{ background: #d1ecf1; border-left-color: #17a2b8; }}
        .list {{ margin-left: 20px; }}
        .list li {{ margin: 8px 0; list-style: none; position: relative; padding-left: 25px; }}
        .list li:before {{ content: "▸"; position: absolute; left: 0; color: {color}; font-weight: bold; }}
        .breakdown {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; }}
        .breakdown-item {{ background: #f9f9f9; padding: 15px; border-radius: 4px; text-align: center; }}
        .breakdown-item .value {{ font-size: 24px; font-weight: bold; color: {color}; }}
        .breakdown-item .label {{ font-size: 12px; color: #666; margin-top: 5px; }}
        footer {{ background: #f9f9f9; padding: 15px 30px; font-size: 12px; color: #999; border-top: 1px solid #eee; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔐 LOCAL AI SCANNER</h1>
            <p>Расширенный анализ безопасности нейросетей</p>
            <div class="score-box">
                Уровень риска: <strong>{level}</strong> ({score}/10)
                <br><small>Сырой счет: {risk.get('raw_score', 0)}/{risk.get('max_possible', 10)}</small>
            </div>
        </header>
        
        <div class="content">
            <div class="row">
                <div class="section">
                    <h2>📋 Информация о модели</h2>
                    <div class="info-grid">
                        <div class="info-item">
                            <label>Путь</label>
                            <value>{results.get('path', 'N/A')}</value>
                        </div>
                        <div class="info-item">
                            <label>Тип</label>
                            <value>{results.get('model_type', 'N/A')}</value>
                        </div>
                        <div class="info-item">
                            <label>Размер</label>
                            <value>{results.get('file_info', {}).get('file_size_mb', 'N/A')} MB</value>
                        </div>
                        <div class="info-item">
                            <label>ID сканирования</label>
                            <value>{results.get('scan_id', 'N/A')}</value>
                        </div>
                    </div>
                </div>
                
                <div class="section">
                    <h2>📊 Детализация оценки</h2>
                    <div class="breakdown">
"""
        
        breakdown = risk.get('breakdown', {})
        for key, value in breakdown.items():
            if isinstance(value, (int, float)):
                html += f"""
                        <div class="breakdown-item">
                            <div class="value">{value:.1f}</div>
                            <div class="label">{key.replace('_', ' ')}</div>
                        </div>
"""
        
        html += """
                    </div>
                </div>
            </div>
"""
        

        warnings = results.get('warnings', [])
        if warnings:
            html += f"""
            <div class="section">
                <h2>⚠️  Предупреждения ({len(warnings)})</h2>
                <ul class="list">
"""
            for w in warnings[:10]:
                html += f"                    <li>{w}</li>\n"
            if len(warnings) > 10:
                html += f"                    <li><strong>... и еще {len(warnings) - 10}</strong></li>\n"
            html += """
                </ul>
            </div>
"""
        

        security = results.get('security_issues', [])
        if security:
            html += f"""
            <div class="section">
                <h2>🔒 Угрозы безопасности ({len(security)})</h2>
                <ul class="list">
"""
            for issue in security[:10]:
                html += f"                    <li>{issue}</li>\n"
            if len(security) > 10:
                html += f"                    <li><strong>... и еще {len(security) - 10}</strong></li>\n"
            html += """
                </ul>
            </div>
"""
        

        backdoor = results.get('backdoor_analysis', {})
        patterns = backdoor.get('suspicious_patterns', [])
        if patterns:
            html += f"""
            <div class="section">
                <h2>🎭 Анализ бэкдоров ({len(patterns)})</h2>
                <ul class="list">
"""
            for pattern in patterns[:8]:
                html += f"                    <li>{pattern}</li>\n"
            if len(patterns) > 8:
                html += f"                    <li><strong>... и еще {len(patterns) - 8}</strong></li>\n"
            html += """
                </ul>
            </div>
"""
        

        recommendations = results.get('recommendations', [])
        if recommendations:
            html += f"""
            <div class="section">
                <h2>💡 Рекомендации ({len(recommendations)})</h2>
                <ul class="list">
"""
            for rec in recommendations[:5]:
                html += f"                    <li>{rec}</li>\n"
            html += """
                </ul>
            </div>
"""
        
        html += f"""
        </div>
        
        <footer>
            <p>Сгенерировано LOCAL AI SCANNER | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </footer>
    </div>
</body>
</html>"""
        
        return html


