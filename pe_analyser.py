import pefile
import math
import sys
import os

def calculate_entropy(data):
    """
    Calculate Shannon entropy of a binary file section.
    Entropy is a measure of randomness; higher values suggest more random (or compressed/encrypted) data.
    """
    if not data:
        return 0
    freq = {b: data.count(b) for b in set(data)}
    length = len(data)
    return -sum((freq[b] / length) * math.log2(freq[b] / length) for b in freq)

def analyse_pe(file_path):
    """
    Analyse a Portable Executable (PE) file for section entropy and imported functions.
    
    Args:
        file_path (str): Path to the PE file to analyse.
    """
    # Validate file existence
    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' does not exist.")
        return

    try:
        # Load the PE file
        pe = pefile.PE(file_path)
    except pefile.PEFormatError:
        print(f"Error: File '{file_path}' is not a valid PE file.")
        return

    print(f"File: {file_path}")
    print("\nSections:")
    for section in pe.sections:
        # Decode section name safely
        name = section.Name.decode(errors='replace').strip('\x00')
        # Calculate entropy
        entropy = calculate_entropy(section.get_data())
        print(f"  Section: {name}, Entropy: {entropy:.2f}")

    print("\nImports:")
    # Check and list imported functions
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors='replace')
            print(f"  {dll_name}:")
            for imp in entry.imports:
                func_name = imp.name.decode(errors='replace') if imp.name else 'None'
                print(f"    {func_name}")
    else:
        print("  No imports found.")

    # Cleanup
    pe.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python pe_analyser.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    analyse_pe(file_path)
