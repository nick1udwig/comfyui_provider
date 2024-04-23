#!/usr/bin/env python3

import argparse
import json
import os
import subprocess
import sys

def run_command(command, cwd=None):
    process = subprocess.run(command, shell=True, cwd=cwd, text=True, capture_output=True)
    if process.returncode != 0:
        raise Exception(f"Command failed: {process.stderr}")
    return process.stdout

def install_rust():
    if subprocess.run("which rustc", shell=True).returncode != 0:
        print("Rust is not installed. Installing now...")
        run_command("curl https://sh.rustup.rs -sSf | sh -s -- -y")
        os.environ["PATH"] += os.pathsep + os.path.expanduser("~/.cargo/bin")
    else:
        print("Rust is already installed.")

def install_cargo():
    if subprocess.run("which cargo", shell=True).returncode != 0:
        print("Cargo is not installed. Installing with Rust...")
        install_rust()
    else:
        print("Cargo is already installed.")

def install_cargo_tool(tool_name, git_url):
    print(f"Installing {tool_name}...")
    run_command(f"cargo install --git {git_url}")

def setup_comfy_ui(git_url, comfyui_path):
    print("Setting up ComfyUI...")
    if os.path.exists(comfyui_path):
        print("Done setting up ComfyUI.")
        return
    print("Cloning ComfyUI from GitHub...")
    run_command(f"git clone {git_url} {comfyui_path}")

    run_command("pip install -r requirements.txt", cwd=comfyui_path)
    #output = subprocess.check_output(["pip", "install", "-r", f"{comfyui_path}/requirements.txt"], text=True)
    #print(f"lol {output}")
    print("Done setting up ComfyUI.")

def install_comfy_ui_manager(comfyui_path):
    print("Setting up ComfyUI-Manager...")
    custom_nodes_dir = os.path.join(comfyui_path, "custom_nodes")
    if os.path.exists(f"{custom_nodes_dir}/ComfyUI-Manager"):
        print("Done setting up ComfyUI-Manager.")
        return

    # Ensure the directory exists
    if not os.path.exists(custom_nodes_dir):
        raise Exception(f"The specified directory does not exist: {custom_nodes_dir}")

    # Clone ComfyUI-Manager into the custom_nodes directory
    print(f"Cloning ComfyUI-Manager into {custom_nodes_dir}...")
    run_command("git clone https://github.com/ltdrdata/ComfyUI-Manager.git", cwd=custom_nodes_dir)

    comfyui_manager_path = os.path.join(custom_nodes_dir, "ComfyUI-Manager")
    run_command("pip install -r requirements.txt", cwd=comfyui_manager_path)

    print("Done setting up ComfyUI-Manager.")

# TODO: need a list of repos or a map from node to node pack or something
# def install_nodes(config_path, comfyui_path):
#     print(f"{os.getcwd()}")
#     comfyui_manager_path = os.path.join(os.path.join(comfyui_path, "custom_nodes"), "ComfyUI-Manager")
#
#     # Load the workflow.json file
#     with open(config_path, "r") as file:
#         workflow = json.load(file)
#
#     # Extract the list of nodes from the workflow
#     nodes = workflow["nodes"]
#
#     # Get list of already-installed nodes using cm-cli.py
#     check_cmd = ["python3", f"{comfyui_manager_path}/cm-cli.py", "simple-show", "installed"]
#     output = subprocess.check_output(check_cmd, text=True)
#     installed_nodes = output.strip().split("\n")
#
#     # Iterate through the nodes
#     for node_id, node_data in nodes.items():
#         node_name = node_data["class_type"]
#
#         if node_name not in installed_nodes:
#             # Install the node using cm-cli.py
#             print(f"Installing node: {node_name}")
#             install_cmd = ["python3", f"{comfyui_manager_path}/cm-cli.py", "install", node_name]
#             subprocess.run(install_cmd)
#         else:
#             print(f"Node already installed: {node_name}")

def start_comfyui(comfyui_path):
    os.chdir(comfyui_path)
    print("Starting ComfyUI server...")
    subprocess.Popen(["python3", "main.py"])
    os.chdir("..")

def main():
    parser = argparse.ArgumentParser(description="Setup ComfyUI with optional configuration")
    parser.add_argument(
        "--config_path",
        default="workflow.json",
        help="Path to the configuration file",
    )
    args = parser.parse_args()

    config_path = args.config_path

    git_url = "https://github.com/comfyanonymous/ComfyUI"
    kit_git_url = "https://github.com/kinode-dao/kit"
    comfyui_path = "comfyui"

    install_rust()
    install_cargo()
    install_cargo_tool("kit", kit_git_url)

    setup_comfy_ui(git_url, comfyui_path)
    install_comfy_ui_manager(comfyui_path)
    # install_nodes(config_path, comfyui_path)
    start_comfyui(comfyui_path)

if __name__ == "__main__":
    main()
