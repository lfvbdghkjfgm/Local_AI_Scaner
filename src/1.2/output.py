import json
from typing import Dict,Any

class Outputer:
    @staticmethod
    def text_format(results: Dict[str,Any]) -> str:
        output = []
        output.append("=" * 70)
        output.append("LOCAL AI SCANNER - РАСШИРЕННЫЙ АНАЛИЗ БЕЗОПАСНОСТИ")
        output.append("=" * 70)
        output.append(f"Модель: {results.get('path', 'N/A')}")
        output.append(f"Тип модели: {results.get('model_type', 'N/A')}")
        output.append(f"Тип сканирования: {results.get('scan_type', 'N/A')}")
        output.append(f"ID сканирования: {results.get('scan_id', 'N/A')}")
        output.append(f"Временная метка: {results.get('timestamp', 'N/A')}")
        output.append("-" * 70)

        file_info = results.get('file_info', {})
        if file_info:
            output.append("ИНФОРМАЦИЯ О ФАЙЛЕ:")
            if 'file_size_mb' in file_info:
                output.append(f"  Размер: {file_info.get('file_size_mb', 'N/A')} MB")
            if 'sha256' in file_info:
                output.append(f"  SHA256: {file_info.get('sha256', 'N/A')[:16]}...")

        risk = results.get('risk_assessment', {})
        output.append("\nОЦЕНКА РИСКА:")
        output.append(f"  Уровень: {risk.get('level', 'N/A')}")
        output.append(f"  Баллы: {risk.get('score', 'N/A')}")

        warnings = results.get('warnings', [])
        if warnings:
            output.append(f"\nПРЕДУПРЕЖДЕНИЯ ({len(warnings)}):")
            for i, warning in enumerate(warnings, 1):
                output.append(f"  {i}. {warning}")

        errors = results.get('errors', [])
        if errors:
            output.append(f"\nОШИБКИ ({len(errors)}):")
            for i, error in enumerate(errors, 1):
                output.append(f"  {i}. {error}")

        security_issues = results.get('security_issues', [])
        if security_issues:
            output.append(f"\nУГРОЗЫ БЕЗОПАСНОСТИ ({len(security_issues)}):")
            for i, issue in enumerate(security_issues, 1):
                output.append(f"    {i}. {issue}")

        backdoor_analysis = results.get('backdoor_analysis', {})
        if backdoor_analysis:
            output.append(f"\nАНАЛИЗ БЭКДОРОВ:")
            output.append(f"  Выполнено проверок: {', '.join(backdoor_analysis.get('performed_checks', []))}")

            patterns = backdoor_analysis.get('suspicious_patterns', [])
            if patterns:
                output.append(f"  ПОДОЗРИТЕЛЬНЫЕ ПАТТЕРНЫ ({len(patterns)}):")
                for i, pattern in enumerate(patterns, 1):
                    output.append(f"    🚨 {i}. {pattern}")
            else:
                output.append("\n  Подозрительные паттерны не обнаружены\n")

        recommendations = results.get('recommendations', [])
        if recommendations:
            output.append(f"\nРЕКОМЕНДАЦИИ ({len(recommendations)}):")
            for i, rec in enumerate(recommendations, 1):
                output.append(f"  {i}. {rec}")

        if risk.get('breakdown'):
            output.append(f"\nДЕТАЛИ ОЦЕНКИ РИСКА:")
            breakdown = risk['breakdown']
            label_map = {
                'format_threat': '  Угроза формата',
                'security_threats': '  Угрозы безопасности',
                'backdoor_patterns': '  Паттерны бэкдоров',
                'critical_threats': '  Критические угрозы',
                'trojan_signatures': '  Сигнатуры троянов',
                'network_operations': '  Сетевые операции',
                'system_calls': '  Опасные системные вызовы'
            }
            for key, value in breakdown.items():
                if key in label_map:
                    label = label_map[key]
                    if isinstance(value, float):
                        output.append(f"{label}: {value:.2f}")
                    else:
                        output.append(f"{label}: {value}")
            
            # Добавить raw score для справки
            if 'raw_score' in risk:
                output.append(f"\n  Сырой счет: {risk['raw_score']} / {risk.get('scale', 10.0)}")

        output.append("=" * 70)
        return "\n".join(output)
    @staticmethod
    def json_format(results: Dict[str, Any]) -> str:
        return json.dumps(results, indent=2, ensure_ascii=False)

    @staticmethod
    def csv_format(results: Dict[str,Any]):
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

        breakdown = risk.get('breakdown', {})
        for key in ['format_threat', 'security_threats', 'backdoor_patterns', 'critical_threats']:
            writer.writerow([key, breakdown.get(key, '')])

        writer.writerow(['warnings_count', len(results.get('warnings', []))])
        writer.writerow(['errors_count', len(results.get('errors', []))])
        writer.writerow(['security_issues_count', len(results.get('security_issues', []))])
        backdoor = results.get('backdoor_analysis', {})
        writer.writerow(['backdoor_patterns_count', len(backdoor.get('suspicious_patterns', []))])
        writer.writerow(['recommendations_count', len(results.get('recommendations', []))])

        if results.get('warnings'):
            writer.writerow(['warnings_preview', ' | '.join(results.get('warnings')[:3])])
        if results.get('errors'):
            writer.writerow(['errors_preview', ' | '.join(results.get('errors')[:3])])
        if backdoor.get('suspicious_patterns'):
            writer.writerow(['backdoor_patterns_preview', ' | '.join(backdoor.get('suspicious_patterns')[:5])])

        return output.getvalue()


