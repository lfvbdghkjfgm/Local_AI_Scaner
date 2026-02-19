# LOCAL AI SCANNER - Advanced Neural Network Security Analysis

A comprehensive security scanning tool designed to detect threats in machine learning models including backdoors, malicious code, and shadow logic patterns. Features advanced weight analysis with 8 statistical metrics and multi-format reporting.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Advanced Analysis](#advanced-analysis)
- [Output Formats](#output-formats)
- [Examples](#examples)
- [Safety Information](#safety-information)
- [Development](#development)
- [Download Releases](#download-releases)
- [Support](#support)

## Overview

LOCAL AI SCANNER is a specialized security tool for analyzing machine learning models at the file level. It performs comprehensive threat detection without requiring internet connectivity, making it ideal for analyzing sensitive or proprietary model files. The scanner uses sophisticated weight analysis, pattern recognition, and statistical methods to identify anomalies that may indicate backdoors, data exfiltration mechanisms, or embedded malicious logic.

## Features

### Core Scanning Capabilities

- **8-Metric Weight Analysis**: Advanced statistical analysis including kurtosis, skewness, entropy, L2 norm, sparsity detection, median analysis, interquartile range, and percentile calculations
- **Shadow Logic Detection**: Identifies suspicious patterns indicative of hidden model behavior
- **Multi-Format Model Support**: Analyzes .pkl, .pt, .pth, .h5, .safetensors, .onnx, .pb, and .zip archive files
- **Directory Scanning**: Batch analysis of multiple model files with comprehensive reporting
- **Risk Scoring System**: Multi-component risk calculation (format risk, security risk, backdoor risk, critical vulnerabilities)
- **Multiple Output Formats**: TEXT, JSON, CSV, and HTML export options

### Analysis Types

1. **Full Scan**: Complete analysis including format verification, security checks, backdoor detection, and weight analysis
2. **Format Analysis**: File format validation and structure integrity checking
3. **Security Analysis**: General security vulnerability detection
4. **Backdoor Detection**: Specialized analysis for backdoor patterns and trigger mechanisms

### Advanced Features

- **Isolated Analysis**: Weight analysis runs in isolated subprocess with resource limits (CPU throttling, RAM limits, timeout protection)
- **Safe for Malicious Files**: Designed to safely handle potentially infected model files
- **Concurrent Processing**: Efficient handling of multiple files
- **Detailed Reporting**: Per-file threat lists, warnings, suspicious patterns, and recommendations
- **Customizable Output**: Choose scanning depth and output verbosity

## System Requirements

### Windows

- **OS**: Windows 7 SP1 or later (Windows 10/11 recommended)
- **Architecture**: 64-bit processor
- **RAM**: Minimum 4 GB (8 GB recommended for large models)
- **Disk Space**: 500 MB for extraction and analysis
- **Python**: 3.8+ (if running from source)

### Linux

- **OS**: Ubuntu 18.04+ / Debian 10+ / CentOS 7+ / Fedora 30+
- **Architecture**: 64-bit processor
- **RAM**: Minimum 4 GB (8 GB recommended)
- **Disk Space**: 500 MB for extraction and analysis
- **Python**: 3.8+ (if running from source)
- **Dependencies**: libc, libstdc++, libgomp


## Installation

### Option 1: Pre-built Executable (Recommended)

#### Windows
1. Download LocalAIScanner.exe from the releases page
2. Extract the ZIP file to your desired location
3. Run `LocalAIScanner.exe` from command prompt

```bash
LocalAIScanner.exe model.pkl
LocalAIScanner.exe ./models
```

#### Linux
1. Download the appropriate archive from releases
2. Extract the archive
3. Run the executable

```bash
./LocalAIScanner model.pkl
./LocalAIScanner ./models
```

### Option 2: From Source

#### Prerequisites
- Python 3.8 or higher
- pip package manager

#### Installation Steps

```bash
# Clone the repository
git clone https://github.com/lfvbdghkjfgm/local-ai-scanner.git
cd local-ai-scanner/src

# Create virtual environment (optional but recommended)
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the scanner
python main.py model.pkl
python main.py ./models
```

## Usage

### Basic Single File Scanning

```bash
# Scan a single model file
LocalAIScanner model.pkl
LocalAIScanner model.h5
LocalAIScanner weights.pt
```

### Directory Scanning

```bash
# Scan all model files in a directory
LocalAIScanner ./models
LocalAIScanner C:\path\to\models

# Scan with full analysis
LocalAIScanner ./models --scan-type full
```

### Command Line Options

```
LocalAIScanner [OPTIONS] PATH

Positional Arguments:
  PATH                     Path to model file, directory, or HuggingFace model ID

Optional Arguments:
  --scan-type {full,format,security,backdoor}
                          Type of scan to perform (default: full)
  -f, --output-format {text,json,csv,html}
                          Output format for results (default: text)
  -o, --output-file FILE  Save detailed results to specified file
  -v, --verbose           Enable verbose output with additional details
  -h, --help              Show help message and exit
```

### Output

#### Console Output (Directory Scan)
```
--------------------------------------------------
     >>>  SCANNING STARTED  <<<
--------------------------------------------------

[1] ./models/model1.pkl
     Risk: [HIGH] (7.2/10)
     Warnings: 5 | Threats found: 3

[2] ./models/model2.h5
     Risk: [CRITICAL] (8.9/10)
     Warnings: 7 | Threats found: 6

...

SUMMARY: 2 files scanned, 1 CRITICAL, 1 HIGH, 0 MEDIUM, 0 LOW
```

#### Detailed Output (Saved to File)
Each file includes:
- Risk assessment with score
- Complete list of warnings
- All detected security threats with descriptions
- Suspicious patterns identified
- Recommendations for remediation

## Advanced Analysis

### Weight Analysis Metrics

The scanner employs 8 statistical metrics for comprehensive weight analysis:

1. **Kurtosis**: Detects abnormal concentration in weight distribution tails (threshold > 10)
2. **Skewness**: Identifies asymmetric weight distributions (threshold |value| > 2)
3. **Shannon Entropy**: Measures disorder in weight distribution (threshold < 4 or > 7)
4. **L2 Norm**: Calculates total weight magnitude (threshold > 1000)
5. **Sparsity**: Percentage of near-zero weights (threshold < 30%)
6. **Median Analysis**: Examines central weight values (threshold-based)
7. **Interquartile Range**: Detects outliers (threshold-based)
8. **Percentile Analysis**: Multi-level outlier detection (25th, 75th, 95th, 99th percentiles)

### Risk Scoring Components

The final risk score combines four risk components:

1. **Format Risk** (0-2.5 points): File structure integrity and format compliance
2. **Security Risk** (0-2.5 points): General security vulnerability detection
3. **Backdoor Risk** (0-2.5 points): Specific backdoor pattern analysis
4. **Critical Issues** (0-2.5 points): Severe vulnerabilities requiring immediate attention

Risk levels are classified as:
- CRITICAL: 8.0-10.0 (Immediate action required)
- HIGH: 6.0-7.9 (Significant threats detected)
- MEDIUM: 4.0-5.9 (Moderate concerns)
- LOW: 0.0-3.9 (Minimal risk or clean)

### File Format Detection

Supported model formats:
- `.pkl` / `.pickle` - Python pickle format
- `.pt` / `.pth` - PyTorch format
- `.h5` - TensorFlow/Keras HDF5 format
- `.safetensors` - Hugging Face SafeTensors format
- `.onnx` - Open Neural Network Exchange format
- `.pb` - TensorFlow Protocol Buffers format
- `.zip` - Archive containing model files

## Output Formats

### Text Format (Default)

Comprehensive human-readable report with all findings:
```
=== RISK ASSESSMENT ===
File: model.pkl
Risk Level: [HIGH]
Risk Score: 7.2/10

=== DETECTED THREATS ===
* Unusual weight distribution (Kurtosis: 15.3)
* Potential backdoor trigger detected
* Suspicious metadata pattern

=== WARNINGS ===
* High entropy in layer: conv1
* Unusual activation patterns
...
```

### JSON Format

Structured machine-readable output suitable for automation and integration:
```json
{
  "file": "model.pkl",
  "risk_level": "HIGH",
  "risk_score": 7.2,
  "format_risk": 2.1,
  "security_risk": 2.4,
  "backdoor_risk": 2.5,
  "critical_issues": 0.2,
  "threats": [...],
  "warnings": [...]
}
```

### CSV Format

Tabular format for spreadsheet analysis and data processing:
```
file,risk_level,risk_score,threats_count,warnings_count,format_risk,security_risk,backdoor_risk
model.pkl,HIGH,7.2,3,5,2.1,2.4,2.5
```

### HTML Format

Formatted visual report for browser viewing and sharing:
- Color-coded risk levels
- Expandable threat details
- Statistical charts
- Summary statistics

## Examples

### Example 1: Quick Scan of a Single Model

```bash
LocalAIScanner model.pkl
```

Console output shows risk level. Detailed results saved to `scan_results_model.pkl.txt`.

### Example 2: Directory Scan with JSON Output

```bash
LocalAIScanner ./models -f json -o results.json
```

Scans all model files in `./models` directory and saves detailed results to `results.json`.

### Example 3: Focused Security Analysis

```bash
LocalAIScanner model.h5 --scan-type security -v
```

Executes focused security analysis with verbose output showing reasoning for detected issues.

### Example 4: Batch Analysis with CSV Export

```bash
LocalAIScanner C:\models --output-format csv -o scan_results.csv
```

Analyzes all models in directory and exports tabular results for further processing.

### Example 5: Comprehensive Analysis with Detailed Report

```bash
LocalAIScanner model.pt --scan-type full -o full_report.txt -v
```

Performs complete analysis including weight metrics and exports detailed report.

## Safety Information

### Threat Model

This scanner is designed to safely handle potentially malicious model files:

- **Isolated Weight Analysis**: Weight analysis runs in a separate subprocess with resource limits
- **CPU Throttling**: Maximum CPU usage caps prevent exploitation
- **Memory Limits**: Analysis memory is restricted to prevent buffer overflow attacks
- **Timeout Protection**: Analysis automatically terminates after timeout period
- **No External Network**: All analysis is local; no data leaves your system
- **Read-Only Access**: Scanner does not modify original files

### What Scanner Does NOT Do

- Does not execute arbitrary code from models
- Does not connect to external servers
- Does not require internet connectivity
- Does not modify scanned files
- Does not store scan results on remote servers
- Does not require special permissions

### Recommended Practices

1. **Scan Before Use**: Always scan models from untrusted sources before deployment
2. **Keep Updated**: Regularly update the scanner to get latest threat definitions
3. **Quarantine Suspicious Models**: Isolate files with HIGH or CRITICAL risk ratings
4. **Manual Review**: For CRITICAL ratings, conduct manual code review before use
5. **Environment Isolation**: Consider running on isolated system for very suspicious files


## Download Releases

### Latest Versions

#### Windows Builds
| Version | Size | Download |
|---------|------|----------|
| **v1.3** | ~465 MB | [LocalAIScanner.zip](releases/1.3/windows/) |
| **v1.2** | ~450 MB | [LocalAIScanner.zip](releases/1.2/windows/) |
| **v1.1** | ~450 MB | [LocalAIScanner.zip](releases/1.1/windows/) |
| **v1.0** | ~450 MB | [LocalAIScanner.zip](releases/1.0/windows/) |

#### Linux Builds
| Version | Size | Download |
|---------|------|----------|
| **v1.3** | ~4.8 GB | Available on request |
| **v1.2** | ~4.5 GB | Available on request |
| **v1.1** | ~4.4 GB | Available on request |
| **v1.0** | ~4.35 GB | [LocalAIScanner.zip](https://drive.google.com/file/d/1TqdbDMb0KsLk8FfnDlOWDiPjVC3MxDR2/view?usp=drive_link) |

#### Source Code
| Version | Location |
|---------|----------|
| **v1.3** | [src/1.3](src/1.3) |
| **v1.2** | [src/1.2](src/1.2) |
| **v1.1** | [src/1.1](src/1.1) |
| **v1.0** | [src/1.0](src/1.0) |

### Release Notes

- [v1.3 Release Notes](RELEASE_v1.3.md) - Directory scanning, multi-file support
- [v1.2 Release Notes](RELEASE_v1.2.md) - Output format enhancements
- [v1.1 Release Notes](RELEASE_v1.1.md) - Improved detection algorithms
- [v1.0 Release Notes](RELEASE_v1.0.md) - Initial release

## Support

### Troubleshooting

#### Model File Not Recognized
- Ensure file extension is correct (.pkl, .h5, .pt, .safetensors, .onnx, .pb, or .zip)
- Verify file is not corrupted: attempt opening with native tools
- Check file permissions (scanner needs read access)

#### High Memory Usage
- For large models, ensure sufficient RAM (check System Requirements)
- Consider scanning on more powerful system
- Reduce scan scope (use --scan-type security for quick check)

#### Permission Denied Errors
- Ensure read permissions on model files and directories
- Run with elevated privileges if necessary
- Check disk space (minimum 500 MB required)

#### Timeout Errors
- Extremely large files may exceed analysis timeout
- Consider splitting large archives before scanning
- Contact support for extended timeout options

### Getting Help

For issues, questions, or suggestions:
1. Check troubleshooting section above
2. Review release notes for version-specific information
3. Submit detailed error logs and file details
4. Include system information (OS, available RAM, Python version)

## Technologies

- **Python**: 3.8+
- **ML Frameworks**: TensorFlow, PyTorch, SafeTensors
- **Analysis**: NumPy, scipy.stats
- **Distribution**: PyInstaller
