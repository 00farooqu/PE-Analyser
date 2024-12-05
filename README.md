# PE File Analyser

A Python script to analyse Portable Executable (PE) files, calculate section entropy, and list imported libraries and functions. This tool is useful for malware analysts and security researchers to detect packed or obfuscated code and understand the behavior of suspicious executables.

---

## Features
- Calculate Shannon entropy for each section in the PE file.
- Extract and display imported libraries and functions.
- Simple and efficient script leveraging the `pefile` library.

---

## Requirements
- Python 3.6+
- Required Python packages (see `requirements.txt`).

---

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/00farooqu/pe-file-analyzer.git
    cd pe-file-analyzer
    ```

2. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

---

## Usage

Run the script with the path to the PE file as an argument:

```bash
python pe_analyser.py <file_path>
```

## Output

## Section Analysis

The script prints the entropy of each section, helping identify potentially packed or encrypted sections.

## Example:
```bash
File: malware_sample.exe
Sections:
  Section: .text, Entropy: 6.34
  Section: .data, Entropy: 3.12
  Section: .rdata, Entropy: 4.56
```
## Import Table

Displays the imported libraries and functions, providing insight into the APIs used.

## Example:
```bash
Imports:
  KERNEL32.dll:
    VirtualAlloc
    WriteProcessMemory
  USER32.dll:
    MessageBoxA
```
## Notes

- High entropy (>7) may indicate packed/encrypted sections.
- Ensure the PE file is valid and accessible before running the script.

#### Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENCE) file for details.

## Disclaimer

This tool is for educational and research purposes only. Use it responsibly and ensure compliance with applicable laws.
