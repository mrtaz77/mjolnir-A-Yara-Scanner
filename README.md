# mjolnir
A yara scanner detecting malwares using yara rules

![logo](https://github.com/mrtaz77/mjolnir/assets/113765142/c9ba3b4b-2cc6-48e6-a14b-8a0b75bcffdb)

## Disclaimer
**Use at your own risk. The author will not be held liable for any illegal activities.**

## How to run
1. Install dependencies via
```bash
pip install -r requirements.txt
```
2. Run using
```py
python3 scanner.py [-h] [-r RULES] [-f FILES]
```

## Usage
```
usage:python3 scanner.py [-h] [-r RULES] [-f FILES]

A tool for scanning files against YARA rules.

options:
  -h, --help            show this help message and exit
  -r RULES, --rules RULES
                        Directory or file containing YARA rules
                        (default: D:\Repo Hub\mjolnir)
  -f FILES, --files FILES
                        Directory or file to be scanned (default:
                        D:\Repo Hub\mjolnir)
```