#!/usr/bin/env python3

import argparse
import os
import sys
import warnings
from pathlib import Path

APP_VERSION = "1.5.1"

def scanning_start_style():
    print("\n" + "-" * 50)
    print(f"     {'>' * 3}  SCANNING STARTED  {'<' * 3}")
    print("-" * 50 + "\n")

def resolve_cli_prog():
    raw_name = Path(sys.argv[0]).name.strip()
    normalized = raw_name.lower()
    known_cli_names = {
        'local-ai-scanner',
        'local-ai-scanner.exe',
        'local-ai-scaner',
        'local-ai-scaner.exe',
        'las',
        'las.exe',
    }
    if normalized in known_cli_names:
        return raw_name
    return 'local-ai-scanner'

def resolve_invoke_cwd() -> Path:
    raw = os.environ.get('LAS_INVOKE_CWD', '').strip()
    if raw:
        p = Path(raw).expanduser()
        if p.exists() and p.is_dir():
            return p.resolve()
    return Path.cwd().resolve()

def resolve_output_path(output_path: str, invoke_cwd: Path) -> Path:
    candidate = Path(output_path).expanduser()
    if candidate.is_absolute():
        return candidate
    return (invoke_cwd / candidate).resolve()

def resolve_model_input(model_arg: str, invoke_cwd: Path) -> str:
    candidate = Path(model_arg).expanduser()
    if candidate.is_absolute():
        return str(candidate)
    preferred = (invoke_cwd / candidate)
    if preferred.exists():
        return str(preferred.resolve())
    if candidate.exists():
        return str(candidate.resolve())
    return model_arg

def render_output(formatter, results, output_format: str, detailed_json: bool) -> str:
    if output_format == 'json':
        return formatter.json_format(results, detailed=detailed_json)
    if output_format == 'csv':
        return formatter.csv_format(results)
    return formatter.text_format(results)

def default_output_name(model_arg: str, output_format: str) -> str:
    suffix = '.txt'
    if output_format == 'json':
        suffix = '.json'
    elif output_format == 'csv':
        suffix = '.csv'
    return f"scan_results_{Path(model_arg).name}{suffix}"

def write_output_file(output_path: Path, payload: str):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(payload)


def main():
    warnings.filterwarnings('ignore', 
                       message='In the future `np.object` will be defined',
                       category=FutureWarning)
    parser = argparse.ArgumentParser(
        prog=resolve_cli_prog(),
        description='LOCAL AI SCANNER - ML Model Security Analysis Tool for Trojan, Malicious Code and Shadow Logic Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
    Usage examples:
      %(prog)s model.pkl
      %(prog)s ./models  (directory scanning)
      %(prog)s --scan-type full model.h5
      %(prog)s --output-format json model.h5
      %(prog)s --output-format json --detailed-json model.h5
      %(prog)s --scan-type security --output-file report.json model.pt
      %(prog)s --verbose "username/suspicious-model"
      %(prog)s --clear-cache
            """
    )
    parser.add_argument('--version', action='version', version=f'%(prog)s v{APP_VERSION}')
    parser.add_argument('model', nargs='?', help='Path to model file, directory, or HuggingFace model ID')
    parser.add_argument('--scan-type', choices=['full', 'format', 'security', 'backdoor'],
                        default='full', help='Scan type (default: full)')
    parser.add_argument('--output-format', '-f', choices=['text', 'json', 'csv'],
                        default='text', help='Output format (default: text)')
    parser.add_argument('--detailed-json', action='store_true',
                        help='Include full raw scan data in JSON output (default: summary JSON)')
    parser.add_argument('--output-file', '-o', help='File to save results')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')
    parser.add_argument('--clear-cache', action='store_true',
                        help='Delete all local scan cache entries before scanning')

    args = parser.parse_args()
    if not args.model and not args.clear_cache:
        parser.print_help()
        return 0

    os.environ.setdefault('TF_CPP_MIN_LOG_LEVEL', '2')
    from scanner import Scanner
    from output import Outputer

    scanner = Scanner(out_form=args.output_format, verb=args.verbose)

    if args.clear_cache:
        clear_result = scanner.clear_cache()
        print(
            "Cache cleared: removed "
            f"{clear_result.get('removed_entries', 0)} entries "
            f"from {clear_result.get('removed_files', 0)} file(s)"
        )

    stale_cleanup_result = scanner.cleanup_stale_cache()
    if args.verbose and stale_cleanup_result.get('removed_entries', 0):
        print(
            "Removed stale cache entries: "
            f"{stale_cleanup_result.get('removed_entries', 0)}"
        )

    if not args.model:
        return 0

    scanning_start_style()

    invoke_cwd = resolve_invoke_cwd()
    scan_target = resolve_model_input(args.model, invoke_cwd)
    path = Path(scan_target)
    is_directory = path.exists() and path.is_dir()

    formatter = Outputer()

    if is_directory:
        results = scanner.scan_directory(scan_target, args.scan_type)
        files_list = formatter.directory_scan_console(results)
        print(files_list)
        
        detailed = render_output(formatter, results, args.output_format, args.detailed_json)
        if args.output_file:
            output_path = resolve_output_path(args.output_file, invoke_cwd)
        else:
            output_path = resolve_output_path(default_output_name(args.model, args.output_format), invoke_cwd)
        write_output_file(output_path, detailed)
        if args.output_format != 'json':
            saved_kind = "Detailed"
        else:
            saved_kind = "Detailed" if args.detailed_json else "Summary"
        print(f"\n{saved_kind} results saved to: {output_path}")
        
        overall_risk_level = results.get('overall_risk_level', 'UNKNOWN')
        if overall_risk_level in ['CRITICAL', 'HIGH']:
            sys.exit(1)
        elif overall_risk_level == 'MEDIUM':
            sys.exit(2)
        else:
            sys.exit(0)
    else:
        results = scanner.scan(scan_target, args.scan_type)
        output = render_output(formatter, results, args.output_format, args.detailed_json)
        print(output)

        if args.output_file:
            output_path = resolve_output_path(args.output_file, invoke_cwd)
        else:
            output_path = resolve_output_path(default_output_name(args.model, args.output_format), invoke_cwd)
        write_output_file(output_path, output)
        print(f"Results saved to: {output_path}")

        risk_level = results.get('risk_assessment', {}).get('level', 'UNKNOWN')
        if risk_level in ['CRITICAL', 'HIGH']:
            sys.exit(1)
        elif risk_level == 'MEDIUM':
            sys.exit(2)
        else:
            sys.exit(0)

if __name__ == '__main__':
    main()



