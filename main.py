# main.py

import os

from scanner.static_analyzer import *
import session
from pathlib import Path
from colorama import Fore, Style, init
init(autoreset=True)

from loguru import logger
logger.remove()  # Remove default logger
logger.add(lambda msg: None, level="WARNING")  # Suppress DEBUG and INFO

def start_cli():
    print(Fore.CYAN + "Welcome to SAULMATE (Mobile Application Exploitation Toolkit)")
    print(Fore.YELLOW + "Type 'help' to get started or 'exit' to quit.")

    while True:
        try:
            command = input(Fore.GREEN + "SAULMATE> ").strip().lower()
            if command == "help":
                print(Fore.RED + """
 ░▒▓███████▓▒░░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓██████████████▓▒░ ░▒▓██████▓▒░▒▓████████▓▒░▒▓████████▓▒░ 
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░        
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░        
 ░▒▓██████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░ ░▒▓█▓▒░   ░▒▓██████▓▒░   
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░        
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░        
░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓████████▓▒░ 
                                                                                                                
                                                                                                                

                        """+Style.RESET_ALL+Fore.WHITE+"""Welcome to SAULMATE (Mobile Application Testing and Exploitation)!

Available Commands:
  help        - Show this help message with available commands.
  exit, q     - Exit the toolkit.
  load -f     - Load a single APK file. Usage: load -f <apk_path>
  load -d     - Load all APKs in a directory. Usage: load -d <dir>
  show apks   - Display all loaded APKs.
  select apks  - Select a specific APK. Usage: select apk <apk_name>
  scan        - Scan the currently loaded APK. Usage: scan

Project Details:
  Description: A toolkit for mobile application exploitation.
  GitHub: https://github.com/karthik-1916/saulmate
  Author: Karthik

Type a command to get started!
                """ + Style.RESET_ALL)
            elif command in ["exit", "q"]:
                print(Fore.RED + "Exiting SAULMATE. Goodbye!")
                break
            elif command == "clear":
                os.system('cls' if os.name == 'nt' else 'clear')
            elif command.startswith("load "):
                args = command.split(" ", 2)
                if len(args) < 3:
                    print(Fore.RED + "Invalid usage. Use 'load -f <apk_path>' or 'load -d <dir>'.")
                    continue

                option, path = args[1], args[2].strip()
                if option == "-f":
                    session.loaded_apk = load_apk(path)
                    print(Fore.GREEN + f"Loaded APK: {path}")
                elif option == "-d":
                    if not os.path.isdir(path):
                        print(Fore.RED + f"Invalid directory: {path}")
                        continue
                    apk_files = [os.path.join(path, f) for f in os.listdir(path) if f.endswith(".apk")]
                    if not apk_files:
                        print(Fore.RED + f"No APK files found in directory: {path}")
                        continue
                    for apk_file in apk_files:
                        session.loaded_apk = load_apk(apk_file)
                        print(Fore.GREEN + f"Loaded APK: {apk_file}")
                else:
                    print(Fore.RED + "Invalid option. Use 'load -f <apk_path>' or 'load -d <dir>'.")

            elif command == "show apks":
                from scanner.static_analyzer import show_apks
                show_apks()

            elif command.startswith("select apks"):
                from scanner.static_analyzer import select_apks
                args = command.split("select apks ", 1)[1]
                select_apks(args)

            elif command.startswith("scan"):
                args = command.split(" ", 1)
                if len(args) > 1 and args[1] == "-cpo":
                    if not session.selected_apks:
                        print(Fore.RED + "[!] No APK selected. Use 'select apk <id|name>' first.")
                        continue

                    for apk_id in session.selected_apks:
                        apk_record = get_apk_by_identifier(apk_id)
                        if not apk_record:
                            print(Fore.RED + f"[!] APK with ID {apk_id} not found.")
                            continue

                        decompiled_dir = Path.home() / "saulmate_output" / sanitize_filename(Path(apk_record['file_path']).stem)
                        analyze_obfuscation_and_proguard(decompiled_dir)
                elif len(args) > 1 and args[1] == "-api":
                    if not session.selected_apks:
                        print(Fore.RED + "[!] No APK selected. Use 'select apk <id|name>' first.")
                        continue

                    for apk_id in session.selected_apks:
                        apk_record = get_apk_by_identifier(apk_id)
                        if not apk_record:
                            print(Fore.RED + f"[!] APK with ID {apk_id} not found.")
                            continue

                        decompiled_dir = Path.home() / "saulmate_output" / sanitize_filename(Path(apk_record['file_path']).stem)
                        find_hardcoded_api_keys(decompiled_dir)
                else:
                    scan_loaded_apk()
            elif command == "":
                continue
            else:
                print(Fore.RED + f"Unknown command: {command}. Type 'help' for assistance.")
        except KeyboardInterrupt:
            print(Fore.RED + "\nExiting SAULMATE. Goodbye!")
            break
        except Exception as e:
            print(Fore.RED + f"An error occurred: {e}")

if __name__ == "__main__":
    start_cli()
