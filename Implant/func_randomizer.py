import os
import re
import random
import string
import shutil

def generate_random_name(length=8):
    """Generates a random name of the given length using letters only."""
    return ''.join(random.choices(string.ascii_letters, k=length))


def update_import_paths(file_content, old_path, new_path):
    """Updates the import path in the given file content."""
    pattern = re.escape(old_path)
    return re.sub(pattern, new_path, file_content)


def get_function_names(file_content):
    """Finds all function definitions in the file content excluding the 'main' function."""
    function_pattern = re.compile(r'func\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(')
    function_names = set(match.group(1) for match in function_pattern.finditer(file_content))
    return {name for name in function_names if name != "main"}


def replace_function_names(file_content, name_map):
    """Replaces all occurrences of function names in the file content according to the name map."""
    for old_name, new_name in name_map.items():
        file_content = re.sub(rf'\b{re.escape(old_name)}\b', new_name, file_content)
    return file_content


def process_go_file(input_path, output_path, old_import_path, new_import_path, global_name_map):
    """Reads, processes, and writes a Go file to a new directory with randomized function names and updated import paths."""
    with open(input_path, 'r') as file:
        content = file.read()

    # Do not modify the package declaration
    package_pattern = re.compile(r'^package\s+([A-Za-z_][A-Za-z0-9_]*)', re.MULTILINE)
    match = package_pattern.search(content)
    if match:
        package_name = match.group(1)

    # Update import paths
    content = update_import_paths(content, old_import_path, new_import_path)

    # Extract and randomize function names
    function_names = get_function_names(content)
    for name in function_names:
        if name not in global_name_map:
            if name[0].isupper():  # Preserve exported status
                global_name_map[name] = generate_random_name().capitalize()
            else:
                global_name_map[name] = generate_random_name().lower()

    # Replace all occurrences of function names using the global name map
    updated_content = replace_function_names(content, global_name_map)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as file:
        file.write(updated_content)

    print(f"Processed {input_path} -> {output_path}: {len(function_names)} functions renamed.")


def process_directory(input_directory, output_directory, old_import_path, new_import_path):
    """Processes all Go files in the specified input directory and outputs them to a new directory."""
    global_name_map = {}  # Store function names across all files

    # First pass: Collect all function names across all files
    for root, _, files in os.walk(input_directory):
        for file_name in files:
            if file_name.endswith('.go'):
                input_path = os.path.join(root, file_name)
                with open(input_path, 'r') as file:
                    content = file.read()
                function_names = get_function_names(content)
                for name in function_names:
                    if name not in global_name_map:
                        if name[0].isupper():  # Preserve exported status
                            global_name_map[name] = generate_random_name().capitalize()
                        else:
                            global_name_map[name] = generate_random_name().lower()

    # Second pass: Apply the renaming to all files
    for root, _, files in os.walk(input_directory):
        for file_name in files:
            if file_name.endswith('.go'):
                input_path = os.path.join(root, file_name)
                relative_path = os.path.relpath(input_path, input_directory)
                output_path = os.path.join(output_directory, relative_path)
                process_go_file(input_path, output_path, old_import_path, new_import_path, global_name_map)


def main():
    """Main entry point of the script."""
    import argparse

    parser = argparse.ArgumentParser(description="Randomize Go function names and update import paths.")
    parser.add_argument('input_directory', help="Path to the directory containing Go files.")
    parser.add_argument('output_directory', help="Path to the directory where processed files will be saved.")
    parser.add_argument('old_import_path', help="The old import path to be replaced.")
    parser.add_argument('new_import_path', help="The new import path to use.")

    args = parser.parse_args()

    if os.path.exists(args.output_directory):
        shutil.rmtree(args.output_directory)  # Clear the output directory if it exists

    process_directory(args.input_directory, args.output_directory, args.old_import_path, args.new_import_path)


if __name__ == "__main__":
    main()
