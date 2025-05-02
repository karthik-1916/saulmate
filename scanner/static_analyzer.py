# scanner/static_analyzer.py

from androguard.core.apk import APK
import hashlib
import os
from lxml import etree
from tabulate import tabulate
import session
from db.connector import *
from pathlib import Path
import re
import subprocess
from colorama import Fore, Style, init
init(autoreset=True)


def calculate_sha256(file_path):
    with open(file_path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

def load_apk(file_path):
    if not os.path.exists(file_path):
        print(Fore.RED + "[!] APK file not found.")
        return None

    try:
        file_name = os.path.basename(file_path)
        file_hash = calculate_sha256(file_path)


        # Insert metadata into DB only if hash not already exists
        conn = get_connection()
        cursor = conn.cursor()

        # Check if hash already exists
        cursor.execute("SELECT * FROM apks WHERE hash = %s", (file_hash,))
        result = cursor.fetchone()

        if result:
            print(Fore.YELLOW + f"[!] APK already loaded: {file_name}")
        else:
            cursor.execute("""
                INSERT INTO apks (hash, file_name, file_path)
                VALUES (%s, %s, %s)
            """, (file_hash, file_name, file_path))
            conn.commit()
            print(Fore.GREEN + f"[✓] APK loaded successfully: {file_name}")

        conn.close()
        return file_name

    except Exception as e:
        print(Fore.RED + f"[!] Failed to load APK: {e}")
        return None


def scan_loaded_apk():
    if not session.selected_apks:
        print(Fore.RED + "[!] No APK selected. Use 'select apk <id|name>' first.")
        return

    print(Fore.CYAN + f"[⚙️] Scanning {len(session.selected_apks)} selected APK(s)...")

    for identifier in session.selected_apks:
        try:
            apk_record = get_apk_by_identifier(identifier)
            if not apk_record:
                print(Fore.RED + f"[!] APK '{identifier}' not found in database.")
                continue

            # Check if last_scanned is already set
            if apk_record.get('last_scanned'):
                print(Fore.YELLOW + f"[✓] APK '{apk_record['file_name']}' was already scanned on {apk_record['last_scanned']}. Skipping...")
                continue

            apk_path = apk_record['file_path']
            apk = APK(apk_path)

            # Perform manifest analysis and decompilation
            manifest_analysis(apk_record['id'], apk)
            decompile_apk(apk_path)

            # Analyze ProGuard and obfuscation
            decompiled_dir = Path.home() / "saulmate_output" / sanitize_filename(Path(apk_path).stem)
            analyze_obfuscation_and_proguard(decompiled_dir)

            # Update last_scanned in the database
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE apks SET last_scanned = NOW() WHERE id = %s",
                (apk_record['id'],)
            )
            conn.commit()
            conn.close()

            print(Fore.GREEN + f"[✓] Updated last_scanned for APK ID {apk_record['id']}.")

        except Exception as e:
            print(Fore.RED + f"[!] Error scanning {identifier}: {e}")

def get_apk_by_identifier(identifier):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    if isinstance(identifier, int):
        cursor.execute("SELECT * FROM apks WHERE id = %s", (identifier,))
    else:
        cursor.execute("SELECT * FROM apks WHERE file_name = %s", (identifier,))

    apk = cursor.fetchone()
    conn.close()
    return apk

def show_apks():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, file_name, last_scanned FROM apks")
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        print(Fore.RED + "[!] No APKs loaded yet.")
        return

    table = []
    for row in rows:
        selected_marker = "★" if row["id"] in session.selected_apks else ""
        last_scanned = row["last_scanned"].strftime("%Y-%m-%d %H:%M:%S") if row["last_scanned"] else "Never"
        table.append([row["id"], row["file_name"], last_scanned, selected_marker])

    print(Fore.CYAN + tabulate(table, headers=["ID", "APK Name", "Last Scanned", "Selected"], tablefmt="grid"))


def select_apks(identifier_str):
    identifiers = [i.strip() for i in identifier_str.split(",")]
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, file_name FROM apks")
    rows = cursor.fetchall()
    conn.close()

    selected_ids = set()

    if "*" in identifiers:  # Select all loaded APKs
        selected_ids.update(row["id"] for row in rows)
    else:
        for item in identifiers:
            for row in rows:
                if str(row["id"]) == item or row["file_name"] == item:
                    selected_ids.add(row["id"])

    if selected_ids:
        session.selected_apks.update(selected_ids)
        print(Fore.GREEN + f"[✓] Selected {len(selected_ids)} APK(s).")
    else:
        print(Fore.RED + "[!] No matching APKs found.")


def sanitize_filename(name):
    # Remove any characters that are not alphanumeric, underscore, or dash
    return re.sub(r'[^\w\-]', '_', name)

def decompile_apk(apk_path):
    apk_path = Path(apk_path).resolve()

    if not apk_path.is_file():
        print(Fore.RED + f"[-] APK file not found: {apk_path}")
        return

    apk_name = sanitize_filename(apk_path.stem)

    output_dir = Path.home() / "saulmate_output" / apk_name
    output_dir.mkdir(parents=True, exist_ok=True)

    jadx_command = [
        "jadx",
        "-d", str(output_dir),
        str(apk_path)
    ]

    print(Fore.CYAN + f"[+] Decompiling {apk_path} to {output_dir} ...")

    try:
        subprocess.run(jadx_command, check=True)
        print(Fore.GREEN + f"[+] Decompilation complete: {output_dir}")
    except Exception as e:
        print(Fore.RED + f"[-] Decompilation failed: {e}")
        return
        

def manifest_analysis(app_id, apk):
    manifest_element = apk.get_android_manifest_xml()
    # Convert the _Element to a string and parse it
    manifest_str = etree.tostring(manifest_element, pretty_print=True, encoding="utf-8", xml_declaration=True)
    root = etree.fromstring(manifest_str)

    # Iterate through the XML structure
    for element in root.iter():
        if element.tag.endswith("application"):  # Match 'application' tag
            attributes = {
                "android:name": element.attrib.get("{http://schemas.android.com/apk/res/android}name", "NULL"),
                "android:allowTaskReparenting": element.attrib.get("{http://schemas.android.com/apk/res/android}allowTaskReparenting", "NULL"),
                "android:allowBackup": element.attrib.get("{http://schemas.android.com/apk/res/android}allowBackup", "NULL"),
                "android:allowClearUserData": element.attrib.get("{http://schemas.android.com/apk/res/android}allowClearUserData", "NULL"),
                "android:allowNativeHeapPointerTagging": element.attrib.get("{http://schemas.android.com/apk/res/android}allowNativeHeapPointerTagging", "NULL"),
                "android:appCategory": element.attrib.get("{http://schemas.android.com/apk/res/android}appCategory", "NULL"),
                "android:backupAgent": element.attrib.get("{http://schemas.android.com/apk/res/android}backupAgent", "NULL"),
                "android:backupInForeground": element.attrib.get("{http://schemas.android.com/apk/res/android}backupInForeground", "NULL"),
                "android:banner": element.attrib.get("{http://schemas.android.com/apk/res/android}banner", "NULL"),
                "android:dataExtractionRules": element.attrib.get("{http://schemas.android.com/apk/res/android}dataExtractionRules", "NULL"),
                "android:debuggable": element.attrib.get("{http://schemas.android.com/apk/res/android}debuggable", "NULL"),
                "android:description": element.attrib.get("{http://schemas.android.com/apk/res/android}description", "NULL"),
                "android:enabled": element.attrib.get("{http://schemas.android.com/apk/res/android}enabled", "NULL"),
                "android:enableOnBackInvokedCallback": element.attrib.get("{http://schemas.android.com/apk/res/android}enableOnBackInvokedCallback", "NULL"),
                "android:extractNativeLibs": element.attrib.get("{http://schemas.android.com/apk/res/android}extractNativeLibs", "NULL"),
                "android:fullBackupContent": element.attrib.get("{http://schemas.android.com/apk/res/android}fullBackupContent", "NULL"),
                "android:fullBackupOnly": element.attrib.get("{http://schemas.android.com/apk/res/android}fullBackupOnly", "NULL"),
                "android:gwpAsanMode": element.attrib.get("{http://schemas.android.com/apk/res/android}gwpAsanMode", "NULL"),
                "android:hasCode": element.attrib.get("{http://schemas.android.com/apk/res/android}hasCode", "NULL"),
                "android:hasFragileUserData": element.attrib.get("{http://schemas.android.com/apk/res/android}hasFragileUserData", "NULL"),
                "android:hardwareAccelerated": element.attrib.get("{http://schemas.android.com/apk/res/android}hardwareAccelerated", "NULL"),
                "android:isGame": element.attrib.get("{http://schemas.android.com/apk/res/android}isGame", "NULL"),
                "android:isMonitoringTool": element.attrib.get("{http://schemas.android.com/apk/res/android}isMonitoringTool", "NULL"),
                "android:killAfterRestore": element.attrib.get("{http://schemas.android.com/apk/res/android}killAfterRestore", "NULL"),
                "android:largeHeap": element.attrib.get("{http://schemas.android.com/apk/res/android}largeHeap", "NULL"),
                "android:label": element.attrib.get("{http://schemas.android.com/apk/res/android}label", "NULL"),
                "android:logo": element.attrib.get("{http://schemas.android.com/apk/res/android}logo", "NULL"),
                "android:manageSpaceActivity": element.attrib.get("{http://schemas.android.com/apk/res/android}manageSpaceActivity", "NULL"),
                "android:networkSecurityConfig": element.attrib.get("{http://schemas.android.com/apk/res/android}networkSecurityConfig", "NULL"),
                "android:permission": element.attrib.get("{http://schemas.android.com/apk/res/android}permission", "NULL"),
                "android:persistent": element.attrib.get("{http://schemas.android.com/apk/res/android}persistent", "NULL"),
                "android:process": element.attrib.get("{http://schemas.android.com/apk/res/android}process", "NULL"),
                "android:restoreAnyVersion": element.attrib.get("{http://schemas.android.com/apk/res/android}restoreAnyVersion", "NULL"),
                "android:requestLegacyExternalStorage": element.attrib.get("{http://schemas.android.com/apk/res/android}requestLegacyExternalStorage", "NULL"),
                "android:requiredAccountType": element.attrib.get("{http://schemas.android.com/apk/res/android}requiredAccountType", "NULL"),
                "android:resizeableActivity": element.attrib.get("{http://schemas.android.com/apk/res/android}resizeableActivity", "NULL"),
                "android:restrictedAccountType": element.attrib.get("{http://schemas.android.com/apk/res/android}restrictedAccountType", "NULL"),
                "android:supportsRtl": element.attrib.get("{http://schemas.android.com/apk/res/android}supportsRtl", "NULL"),
                "android:taskAffinity": element.attrib.get("{http://schemas.android.com/apk/res/android}taskAffinity", "NULL"),
                "android:testOnly": element.attrib.get("{http://schemas.android.com/apk/res/android}testOnly", "NULL"),
                "android:theme": element.attrib.get("{http://schemas.android.com/apk/res/android}theme", "NULL"),
                "android:uiOptions": element.attrib.get("{http://schemas.android.com/apk/res/android}uiOptions", "NULL"),
                "android:usesCleartextTraffic": element.attrib.get("{http://schemas.android.com/apk/res/android}usesCleartextTraffic", "NULL"),
                "android:vmSafeMode": element.attrib.get("{http://schemas.android.com/apk/res/android}vmSafeMode", "NULL"),
            }

            # Check for meta-data tags inside the application tag
            metadata_list = []
            for child in element:
                if child.tag.endswith("meta-data"):
                    meta_data_attributes = {
                        "android:name": child.attrib.get("{http://schemas.android.com/apk/res/android}name", "NULL"),
                        "android:resource": child.attrib.get("{http://schemas.android.com/apk/res/android}resource", "NULL"),
                        "android:value": child.attrib.get("{http://schemas.android.com/apk/res/android}value", "NULL"),
                    }
                    metadata_list.append(meta_data_attributes)

            save_application_to_db(app_id, 1, attributes, metadata_list)

        elif element.tag.endswith("activity"):  # Match 'activity' tag
            attributes = {
                "android:name": element.attrib.get("{http://schemas.android.com/apk/res/android}name", "NULL"),
                "android:allowEmbedded": element.attrib.get("{http://schemas.android.com/apk/res/android}allowEmbedded", "NULL"),
                "android:allowTaskReparenting": element.attrib.get("{http://schemas.android.com/apk/res/android}allowTaskReparenting", "NULL"),
                "android:alwayRetainTaskState": element.attrib.get("{http://schemas.android.com/apk/res/android}alwaysRetainTaskState", "NULL"),
                "android:autoRemoveFromRecents": element.attrib.get("{http://schemas.android.com/apk/res/android}autoRemoveFromRecents", "NULL"),
                "android:banner": element.attrib.get("{http://schemas.android.com/apk/res/android}banner", "NULL"),
                "android:canDisplayOnRemoteDevice": element.attrib.get("{http://schemas.android.com/apk/res/android}canDisplayOnRemoteDevice", "NULL"),
                "android:clearTaskOnLaunch": element.attrib.get("{http://schemas.android.com/apk/res/android}clearTaskOnLaunch", "NULL"),
                "android:colorMode": element.attrib.get("{http://schemas.android.com/apk/res/android}colorMode", "NULL"),
                "android:configChanges": element.attrib.get("{http://schemas.android.com/apk/res/android}configChanges", "NULL"),
                "android:directBootAware": element.attrib.get("{http://schemas.android.com/apk/res/android}directBootAware", "NULL"),
                "android:documentLaunchMode": element.attrib.get("{http://schemas.android.com/apk/res/android}documentLaunchMode", "NULL"),
                "android:enabled": element.attrib.get("{http://schemas.android.com/apk/res/android}enabled", "NULL"),
                "android:enableOnBackInvokedCallback": element.attrib.get("{http://schemas.android.com/apk/res/android}enableOnBackInvokedCallback", "NULL"),
                "android:excludesFromRecents": element.attrib.get("{http://schemas.android.com/apk/res/android}excludesFromRecents", "NULL"),
                "android:exported": element.attrib.get("{http://schemas.android.com/apk/res/android}exported", "NULL"),
                "android:finishOnTaskLaunch": element.attrib.get("{http://schemas.android.com/apk/res/android}finishOnTaskLaunch", "NULL"),
                "android:hardwareAccelerated": element.attrib.get("{http://schemas.android.com/apk/res/android}hardwareAccelerated", "NULL"),
                "android:icon": element.attrib.get("{http://schemas.android.com/apk/res/android}icon", "NULL"),
                "android:immersive": element.attrib.get("{http://schemas.android.com/apk/res/android}immersive", "NULL"),
                "android:label": element.attrib.get("{http://schemas.android.com/apk/res/android}label", "NULL"),
                "android:launchMode": element.attrib.get("{http://schemas.android.com/apk/res/android}launchMode", "NULL"),
                "android:lockTaskMode": element.attrib.get("{http://schemas.android.com/apk/res/android}lockTaskMode", "NULL"),
                "android:maxRecents": element.attrib.get("{http://schemas.android.com/apk/res/android}maxRecents", 16),
                "android:maxAspectRatio": element.attrib.get("{http://schemas.android.com/apk/res/android}maxAspectRatio", 1.33),
                "android:multiprocess": element.attrib.get("{http://schemas.android.com/apk/res/android}multiprocess", "NULL"),
                "android:noHistory": element.attrib.get("{http://schemas.android.com/apk/res/android}noHistory", "NULL"),
                "android:parentActivityName": element.attrib.get("{http://schemas.android.com/apk/res/android}parentActivityName", "NULL"),
                "android:persistableMode": element.attrib.get("{http://schemas.android.com/apk/res/android}persistableMode", "NULL"),
                "android:permission": element.attrib.get("{http://schemas.android.com/apk/res/android}permission", "NULL"),
                "android:process": element.attrib.get("{http://schemas.android.com/apk/res/android}process", "NULL"),
                "android:relinquishTaskIdentity": element.attrib.get("{http://schemas.android.com/apk/res/android}relinquishTaskIdentity", "NULL"),
                "android:requireContentUriPermissionFromCaller": element.attrib.get("{http://schemas.android.com/apk/res/android}requireContentUriPermissionFromCaller", "NULL"),
                "android:resizeableActivity": element.attrib.get("{http://schemas.android.com/apk/res/android}resizeableActivity", "NULL"),
                "android:screenOrientation": element.attrib.get("{http://schemas.android.com/apk/res/android}screenOrientation", "NULL"),
                "android:showForAllUsers": element.attrib.get("{http://schemas.android.com/apk/res/android}showForAllUsers", "NULL"),
                "android:stateNotNeeded": element.attrib.get("{http://schemas.android.com/apk/res/android}stateNotNeeded", "NULL"),
                "android:supportsPictureInPicture": element.attrib.get("{http://schemas.android.com/apk/res/android}supportsPictureInPicture", "NULL"),
                "android:taskAffinity": element.attrib.get("{http://schemas.android.com/apk/res/android}taskAffinity", "NULL"),
                "android:theme": element.attrib.get("{http://schemas.android.com/apk/res/android}theme", "NULL"),
                "android:uiOptions": element.attrib.get("{http://schemas.android.com/apk/res/android}uiOptions", "NULL"),
                "android:windowSoftInputMode": element.attrib.get("{http://schemas.android.com/apk/res/android}windowSoftInputMode", "NULL"),
            }

            meta_data_list = []
            for child in element:
                if child.tag.endswith("meta-data"):
                    meta_data = {
                        "android:name": child.attrib.get("{http://schemas.android.com/apk/res/android}name", "NULL"),
                        "android:resource": child.attrib.get("{http://schemas.android.com/apk/res/android}resource", "NULL"),
                        "android:value": child.attrib.get("{http://schemas.android.com/apk/res/android}value", "NULL"),
                    }
                    meta_data_list.append(meta_data)

            save_activity(app_id, attributes, meta_data_list)

        elif element.tag.endswith("service"):  # Match 'service' tag
            attributes = {
                "android:name": element.attrib.get("{http://schemas.android.com/apk/res/android}name", "NULL"),
                "android:description": element.attrib.get("{http://schemas.android.com/apk/res/android}description", "NULL"),
                "android:directBootAware": element.attrib.get("{http://schemas.android.com/apk/res/android}directBootAware", "NULL"),
                "android:enabled": element.attrib.get("{http://schemas.android.com/apk/res/android}enabled", "NULL"),
                "android:exported": element.attrib.get("{http://schemas.android.com/apk/res/android}exported", "NULL"),
                "android:foregroundServiceType": element.attrib.get("{http://schemas.android.com/apk/res/android}foregroundServiceType", "NULL"),
                "android:isolatedProcess": element.attrib.get("{http://schemas.android.com/apk/res/android}isolatedProcess", "NULL"),
                "android:label": element.attrib.get("{http://schemas.android.com/apk/res/android}label", "NULL"),
                "android:permission": element.attrib.get("{http://schemas.android.com/apk/res/android}permission", "NULL"),
                "android:process": element.attrib.get("{http://schemas.android.com/apk/res/android}process", "NULL"),
                "android:stopWithTask": element.attrib.get("{http://schemas.android.com/apk/res/android}stopWithTask", "NULL"),
            }


            # Check for meta-data tags inside the application tag
            meta_data_list = []
            for child in element:
                if child.tag.endswith("meta-data"):
                    meta_data_attributes = {
                        "android:name": child.attrib.get("{http://schemas.android.com/apk/res/android}name", "NULL"),
                        "android:resource": child.attrib.get("{http://schemas.android.com/apk/res/android}resource", "NULL"),
                        "android:value": child.attrib.get("{http://schemas.android.com/apk/res/android}value", "NULL"),
                    }
                    meta_data_list.append(meta_data_attributes)
            save_service(app_id, attributes, meta_data_list)

        elif element.tag.endswith("receiver"):  # Match 'receiver' tag
            attributes = {
                "android:name": element.attrib.get("{http://schemas.android.com/apk/res/android}name", "NULL"),
                "android:directBootAware": element.attrib.get("{http://schemas.android.com/apk/res/android}directBootAware", "NULL"),
                "android:enabled": element.attrib.get("{http://schemas.android.com/apk/res/android}enabled", "NULL"),
                "android:exported": element.attrib.get("{http://schemas.android.com/apk/res/android}exported", "NULL"),
                "android:label": element.attrib.get("{http://schemas.android.com/apk/res/android}label", "NULL"),
                "android:permission": element.attrib.get("{http://schemas.android.com/apk/res/android}permission", "NULL"),
                "android:process": element.attrib.get("{http://schemas.android.com/apk/res/android}process", "NULL"),
            }


            # Check for meta-data tags inside the application tag
            meta_data_list = []
            for child in element:
                if child.tag.endswith("meta-data"):
                    meta_data_attributes = {
                        "android:name": child.attrib.get("{http://schemas.android.com/apk/res/android}name", "NULL"),
                        "android:resource": child.attrib.get("{http://schemas.android.com/apk/res/android}resource", "NULL"),
                        "android:value": child.attrib.get("{http://schemas.android.com/apk/res/android}value", "NULL"),
                    }
                    meta_data_list.append(meta_data_attributes)
            save_receiver(app_id, attributes, meta_data_list)


        elif element.tag.endswith("provider"):  # Match 'provider' tag
            attributes = {
                "android:authorities": element.attrib.get("{http://schemas.android.com/apk/res/android}authorities", "NULL"),
                "android:enabled": element.attrib.get("{http://schemas.android.com/apk/res/android}enabled", "NULL"),
                "android:directBootAware": element.attrib.get("{http://schemas.android.com/apk/res/android}directBootAware", "NULL"),
                "android:exported": element.attrib.get("{http://schemas.android.com/apk/res/android}exported", "NULL"),
                "android:grantUriPermissions": element.attrib.get("{http://schemas.android.com/apk/res/android}grantUriPermissions", "NULL"),
                "android:initOrder": element.attrib.get("{http://schemas.android.com/apk/res/android}initOrder", None),
                "android:label": element.attrib.get("{http://schemas.android.com/apk/res/android}label", "NULL"),
                "android:multiprocess": element.attrib.get("{http://schemas.android.com/apk/res/android}multiprocess", "NULL"),
                "android:name": element.attrib.get("{http://schemas.android.com/apk/res/android}name", "NULL"),
                "android:permission": element.attrib.get("{http://schemas.android.com/apk/res/android}permission", "NULL"),
                "android:process": element.attrib.get("{http://schemas.android.com/apk/res/android}process", "NULL"),
                "android:readPermission": element.attrib.get("{http://schemas.android.com/apk/res/android}readPermission", "NULL"),
                "android:syncable": element.attrib.get("{http://schemas.android.com/apk/res/android}syncable", "NULL"),
                "android:writePermission": element.attrib.get("{http://schemas.android.com/apk/res/android}writePermission", "NULL"),
            }

            # Check for meta-data tags inside the application tag
            meta_data_list = []
            for child in element:
                if child.tag.endswith("meta-data"):
                    meta_data_attributes = {
                        "android:name": child.attrib.get("{http://schemas.android.com/apk/res/android}name", "NULL"),
                        "android:resource": child.attrib.get("{http://schemas.android.com/apk/res/android}resource", "NULL"),
                        "android:value": child.attrib.get("{http://schemas.android.com/apk/res/android}value", "NULL"),
                    }
                    meta_data_list.append(meta_data_attributes)
            save_provider(app_id, attributes, meta_data_list)


        elif element.tag.endswith("uses-permission"):  # Match 'uses-permission' tag
            permission_name = element.attrib.get("{http://schemas.android.com/apk/res/android}name", "NULL")

def is_obfuscated_name(name):
    return bool(re.fullmatch(r'[a-zA-Z]{1,2}', name))

def check_proguard_files(decompiled_dir):
    proguard_indicators = ["mapping.txt", "proguard.cfg", "proguard-project.txt"]
    found = []
    for root, _, files in os.walk(decompiled_dir):
        for file in files:
            if file in proguard_indicators:
                found.append(os.path.join(root, file))
    return found

def scan_for_obfuscation(decompiled_dir):
    obfuscated_classes = 0
    obfuscated_methods = 0
    class_names = set()
    method_names = set()

    for root, _, files in os.walk(decompiled_dir):
        for file in files:
            if file.endswith(".java"):
                with open(os.path.join(root, file), errors="ignore") as f:
                    lines = f.readlines()
                    for line in lines:
                        # Detect class names
                        class_match = re.search(r'\bclass\s+([a-zA-Z_][a-zA-Z0-9_]*)', line)
                        if class_match:
                            name = class_match.group(1)
                            class_names.add(name)
                            if is_obfuscated_name(name):
                                obfuscated_classes += 1
                        # Detect method names
                        method_match = re.findall(r'\b(?:public|private|protected)?\s+[a-zA-Z0-9_\[\]]+\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', line)
                        for name in method_match:
                            method_names.add(name)
                            if is_obfuscated_name(name):
                                obfuscated_methods += 1

    return {
        "obfuscated_classes": obfuscated_classes,
        "obfuscated_methods": obfuscated_methods,
        "total_classes": len(class_names),
        "total_methods": len(method_names)
    }

def find_hardcoded_api_keys(decompiled_dir):
    print(Fore.CYAN + f"[+] Searching for hardcoded API keys in: {decompiled_dir}")
    api_key_patterns = [
    # Google API Key (starts with AIza and is exactly 39 characters long)
    r'AIza[0-9A-Za-z\-_]{35}',

    # Firebase Cloud Messaging Server Key
    r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',

    # Stripe API Keys (test and live)
    r'sk_live_[0-9a-zA-Z]{24}',
    r'sk_test_[0-9a-zA-Z]{24}',

    # Amazon AWS Access Key ID and Secret
    r'AKIA[0-9A-Z]{16}',  # Access Key ID
    r'(?i)aws(.{0,20})?(secret|key)?[\'"\s:=]+[0-9a-zA-Z/+]{40}',  # Secret Access Key

    # Slack Token
    r'xox[baprs]-([0-9a-zA-Z]{10,48})?',

    # Generic Bearer/JWT tokens
    r'(?i)bearer\s+[A-Za-z0-9\-_.]+?\.[A-Za-z0-9\-_.]+?\.[A-Za-z0-9\-_.]+',

    # GitHub Token
    r'ghp_[0-9a-zA-Z]{36}',

    # Facebook Access Token
    r'EAACEdEose0cBA[0-9A-Za-z]+',

    # Twilio API Key
    r'SK[0-9a-fA-F]{32}',

    # Generic patterns (slightly stricter)
    r'(?i)(api|access|auth|secret|token)[\'"\s:=]{1,5}[\'"]?[A-Za-z0-9_\-]{20,}[\'"]?',
]

    matches = []

    for root, _, files in os.walk(decompiled_dir):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
                    for pattern in api_key_patterns:
                        found = re.findall(pattern, content)
                        if found:
                            matches.extend([(file_path, key) for key in found])
            except Exception as e:
                print(Fore.RED + f"[!] Error reading file {file_path}: {e}")

    if matches:
        print(Fore.YELLOW + "[!] Hardcoded API keys found:")
        for file_path, key in matches:
            print(Fore.YELLOW + f"   - File: {file_path}, Key: {key}")
    else:
        print(Fore.GREEN + "[+] No hardcoded API keys found.")

def analyze_obfuscation_and_proguard(decompiled_dir):
    print(Fore.CYAN + f"[+] Scanning decompiled APK in: {decompiled_dir}")

    proguard_files = check_proguard_files(decompiled_dir)
    if (proguard_files):
        print(Fore.YELLOW + "[!] ProGuard configuration files found:")
        for f in proguard_files:
            print(Fore.YELLOW + "   -", f)
    else:
        print(Fore.RED + "[-] No ProGuard files found.")

    obf_result = scan_for_obfuscation(decompiled_dir)
    print(Fore.CYAN + f"[+] Obfuscation detection result:")
    print(Fore.CYAN + f"    - Obfuscated Classes: {obf_result['obfuscated_classes']} / {obf_result['total_classes']}")
    print(Fore.CYAN + f"    - Obfuscated Methods: {obf_result['obfuscated_methods']} / {obf_result['total_methods']}")

    if obf_result["obfuscated_classes"] > 0 or obf_result["obfuscated_methods"] > 0:
        print(Fore.YELLOW + "[!] APK is likely obfuscated.")
    else:
        print(Fore.GREEN + "[+] No significant obfuscation detected.")

    find_hardcoded_api_keys(decompiled_dir)

