import os
import json
import subprocess

with open('.vscode/launch.json') as f:
    launch_config = json.load(f)

workspace_folder = os.getcwd()
output_base = os.path.join(workspace_folder, 'dist')
os.makedirs(output_base, exist_ok=True)

language_map = {
    "-b": "binary",
    "-c": "cpp",
    "-n": "csharp",
    "-d": "dart",
    "-g": "go",
    "-j": "java",
    "-t": "json",
    "--jsonschema": "jsonschema",
    "--kotlin": "kotlin",
    "--kotlin-kmp": "kotlin-kmp",
    "--lobster": "lobster",
    "-l": "lua",
    "--nim": "nim",
    "--php": "php",
    "--proto": "proto",
    "-p": "python",
    "-r": "rust",
    "--swift": "swift",
    "-T": "typescript"
}

def extract_language(args):
    for arg in args:
        if arg in language_map:
            return language_map[arg]
    return "unknown"

def is_preserve_case(args):
    return "--preserve-case" in args

def replace_workspace_vars(s):
    return s.replace("${workspaceFolder}", workspace_folder)

for config in launch_config.get("configurations", []):
    args = [replace_workspace_vars(arg) for arg in config["args"]]
    program = replace_workspace_vars(config["program"])
    cwd = replace_workspace_vars(config["cwd"])

    language = extract_language(args)
    if not language:
        continue

    preserve_case = is_preserve_case(args)
    variant = f"{language}_preserve_case" if preserve_case else language
    output_dir = os.path.join(output_base, variant)
    os.makedirs(output_dir, exist_ok=True)

    processed_args = []
    skip_next = False
    for i, arg in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if arg == "-o":
            processed_args.extend(["-o", output_dir])
            skip_next = True
        else:
            processed_args.append(arg)

    # Resolve the .fbs file relative to cwd if needed
    for i, arg in enumerate(processed_args):
        if arg.endswith(".fbs") and not os.path.isabs(arg):
            processed_args[i] = os.path.join(cwd, arg)

    try:
        subprocess.run([program] + processed_args, check=True, cwd=cwd)
        print(f"Generated output for {variant} in {output_dir}")
    except subprocess.CalledProcessError as e:
        print(f"Error generating output for {variant}: {e}")