#!/usr/bin/env python3

import argparse
import sys
import warnings
from pathlib import Path

APP_VERSION = "1.3"

def scanning_start_style():
    print("\n" + "-" * 50)
    print(f"     {'>' * 3}  SCANNING STARTED  {'<' * 3}")
    print("-" * 50 + "\n")


def main():
    warnings.filterwarnings('ignore', 
                       message='In the future `np.object` will be defined',
                       category=FutureWarning)
    parser = argparse.ArgumentParser(
        description='LOCAL AI SCANNER - ML Model Security Analysis Tool for Trojan and Backdoor Detection',
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
            """
    )
    parser.add_argument('--version', action='version', version=f'%(prog)s v{APP_VERSION}')
    parser.add_argument('model', help='Path to model file, directory, or HuggingFace model ID')
    parser.add_argument('--scan-type', choices=['full', 'format', 'security', 'backdoor'],
                        default='full', help='Scan type (default: full)')
    parser.add_argument('--output-format', '-f', choices=['text', 'json', 'csv'],
                        default='text', help='Output format (default: text)')
    parser.add_argument('--detailed-json', action='store_true',
                        help='Include full raw scan data in JSON output (default: summary JSON)')
    parser.add_argument('--output-file', '-o', help='File to save results')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')

    args = parser.parse_args()
    from scanner import Scanner
    from output import Outputer
    scanning_start_style()

    path = Path(args.model)
    is_directory = path.exists() and path.is_dir()
    
    scanner = Scanner(out_form=args.output_format, verb=args.verbose)
    formatter = Outputer()

    if is_directory:
        results = scanner.scan_directory(str(path), args.scan_type)
        files_list = formatter.directory_scan_console(results)
        print(files_list)
        
        if args.output_file:
            if args.output_format == 'json':
                detailed = formatter.json_format(results, detailed=args.detailed_json)
            elif args.output_format == 'csv':
                detailed = formatter.csv_format(results)
            else:
                detailed = formatter.text_format(results)
            
            with open(args.output_file, 'w', encoding='utf-8') as f:
                f.write(detailed)
            if args.output_format != 'json':
                saved_kind = "Detailed"
            else:
                saved_kind = "Detailed" if args.detailed_json else "Summary"
            print(f"\n{saved_kind} results saved to: {args.output_file}")
        else:
            default_output = f"scan_results_{Path(args.model).name}.txt"
            if args.output_format == 'json':
                detailed = formatter.json_format(results, detailed=args.detailed_json)
                default_output = f"scan_results_{Path(args.model).name}.json"
            elif args.output_format == 'csv':
                detailed = formatter.csv_format(results)
                default_output = f"scan_results_{Path(args.model).name}.csv"
            else:
                detailed = formatter.text_format(results)
            
            with open(default_output, 'w', encoding='utf-8') as f:
                f.write(detailed)
            if args.output_format != 'json':
                saved_kind = "Detailed"
            else:
                saved_kind = "Detailed" if args.detailed_json else "Summary"
            print(f"{saved_kind} results saved to: {default_output}")
        
        overall_risk_level = results.get('overall_risk_level', 'UNKNOWN')
        if overall_risk_level in ['CRITICAL', 'HIGH']:
            sys.exit(1)
        elif overall_risk_level == 'MEDIUM':
            sys.exit(2)
        else:
            sys.exit(0)
    else:
        results = scanner.scan(args.model, args.scan_type)
        
        if args.output_format == 'json':
            output = formatter.json_format(results, detailed=args.detailed_json)
        elif args.output_format == 'csv':
            output = formatter.csv_format(results)
        else:
            output = formatter.text_format(results)

        if args.output_file:
            with open(args.output_file, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"Results saved to: {args.output_file}")
        else:
            print(output)

        risk_level = results.get('risk_assessment', {}).get('level', 'UNKNOWN')
        if risk_level in ['CRITICAL', 'HIGH']:
            sys.exit(1)
        elif risk_level == 'MEDIUM':
            sys.exit(2)
        else:
            sys.exit(0)

if __name__ == '__main__':
    main()



