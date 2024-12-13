import os
import re
import random
import string
import shutil


def random_name(length=8, capitalize=False):
    """Generate a random string of letters of given length."""
    name = ''.join(random.choices(string.ascii_lowercase, k=length))
    return name.capitalize() if capitalize else name


def rename_functions(file_content):
    """Rename all functions in the provided file content, preserving exported function capitalization."""

    # Match function declarations like: func MyFunc(args) or func myFunc(args)
    pattern = re.compile(r'\bfunc\s+(\w+)\s*\(')

    # Store a map of original function names to new function names
    name_map = {}

    def replace_function_name(match):
        original_name = match.group(1)

        if original_name not in name_map:
            is_exported = original_name[0].isupper()
            new_name = random_name(capitalize=is_exported)
            name_map[original_name] = new_name
        else:
            new_name = name_map[original_name]

        return f"func {new_name}("

    # Replace function definitions in the file content
    updated_content = re.sub(pattern, replace_function_name, file_content)

    # Replace all other references to the renamed functions in the file
    for original_name, new_name in name_map.items():
        if original_name != "main":
            updated_content = re.sub(rf'\b{re.escape(original_name)}\b', new_name, updated_content)

    return updated_content, name_map


def process_file(input_path, output_path):
    """Process a single Go file, renaming function names and copying to the output path."""
    with open(input_path, 'r', encoding='utf-8') as file:
        content = file.read()

    updated_content, name_map = rename_functions(content)

    with open(output_path, 'w', encoding='utf-8') as file:
        file.write(updated_content)

    return name_map


def process_directory(input_dir, output_dir):
    """Copy all files from input_dir to output_dir and rename function names in .go files."""

    # Copy the directory structure first
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)

    shutil.copytree(input_dir, output_dir, dirs_exist_ok=True)

    name_maps = {}

    for root, _, files in os.walk(output_dir):
        for file_name in files:
            if file_name.endswith('.go'):
                input_path = os.path.join(root, file_name)
                print(f"Processing file: {input_path}")

                name_map = process_file(input_path, input_path)  # In-place processing of copied file
                name_maps[input_path] = name_map

    return name_maps


def main():
    input_dir = "../Implant/"  # Directory containing original source files
    output_dir = "../Implant/preprocessor"  # Directory to hold preprocessed files

    print(f"Copying files from {input_dir} to {output_dir} and renaming functions...")

    name_maps = process_directory(input_dir, output_dir)

    print("Function renaming complete.")
    for file_path, name_map in name_maps.items():
        print(f"File: {file_path}")
        for original_name, new_name in name_map.items():
            print(f"  {original_name} -> {new_name}")


if __name__ == "__main__":
    main()
