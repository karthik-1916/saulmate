# main.py

import os

from scanner.static_analyzer import load_apk, scan_loaded_apk
import session


from loguru import logger
logger.remove()  # Remove default logger
logger.add(lambda msg: None, level="WARNING")  # Suppress DEBUG and INFO



def start_cli():
    print("Welcome to MAET (Mobile Application Exploitation Toolkit)")
    print("Type 'help' to get started or 'exit' to quit.")

    while True:
        try:
            command = input("MAET> ").strip().lower()
            if command == "help":
                print("""
  __  __    _    _______ 
 |  \/  |  / \  | ____\ \\
 | |\/| | / _ \ |  _|  | |
 | |  | |/ ___ \| |___ / /
 |_|  |_/_/   \_\_____/_/ 

      .-"      "-.
     /            \\
    |,  .-.  .-.  ,|
    | )(_o/  \o_)( |
    |/     /\     \|
    (_     ^^     _)
     \__|IIIIII|__/
      | \IIIIII/ |
      \          /
       `--------`

Welcome to MAET (Mobile Application Exploitation Toolkit)!

Available Commands:
  help        - Show this help message with available commands.
  exit, q     - Exit the toolkit.
  load        - Load an APK file. Usage: load <apk_path>
  show apks   - Display all loaded APKs.
  select apk  - Select a specific APK. Usage: select apk <apk_name>
  scan        - Scan the currently loaded APK. Usage: scan

Project Details:
  Description: A toolkit for mobile application exploitation.
  GitHub: https://github.com/your-repo/maet
  Author: Dimitri

Type a command to get started!
                """)
            elif command in ["exit", "q"]:
                print("Exiting MAET. Goodbye!")
                break
            
            elif command.startswith("load "):
                apk_path = command.split("load ", 1)[1].strip()
                session.loaded_apk = load_apk(apk_path)

            elif command == "show apk":
                from scanner.static_analyzer import show_apks
                show_apks()

            elif command.startswith("select apk"):
                from scanner.static_analyzer import select_apks
                args = command.split("select apk ", 1)[1]
                select_apks(args)

            elif command == "scan":
                scan_loaded_apk()
            elif command == "":
                continue
            else:
                print(f"Unknown command: {command}. Type 'help' for assistance.")
        except KeyboardInterrupt:
            print("\nExiting MAET. Goodbye!")
            break
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    start_cli()
