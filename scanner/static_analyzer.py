# scanner/static_analyzer.py

from androguard.core.apk import APK
from db.connector import get_connection
import hashlib
import os
from tabulate import tabulate
import session
from datetime import datetime
def calculate_sha256(file_path):
    with open(file_path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

def load_apk(file_path):
    if not os.path.exists(file_path):
        print("[!] APK file not found.")
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
            print(f"[!] APK already loaded: {file_name}")
        else:
            cursor.execute("""
                INSERT INTO apks (hash, file_name, file_path)
                VALUES (%s, %s, %s)
            """, (file_hash, file_name, file_path))
            conn.commit()
            print(f"[✓] APK loaded successfully: {file_name}")

        conn.close()
        return file_name

    except Exception as e:
        print(f"[!] Failed to load APK: {e}")
        return None


def scan_loaded_apk():
    if not session.selected_apks:
        print("[!] No APK selected. Use 'select apk <id|name>' first.")
        return

    print(f"[⚙️] Scanning {len(session.selected_apks)} selected APK(s)...")

    for identifier in session.selected_apks:
        try:
            apk_record = get_apk_by_identifier(identifier)
            if not apk_record:
                print(f"[!] APK '{identifier}' not found in database.")
                continue

            apk_path = apk_record['file_name']
            apk = APK(apk_path)

            manifest = apk.get_android_manifest_xml()
            # print(f"manifest: {manifest}")
            print()
            return
        except Exception as e:
            print(f"[!] Error scanning {identifier}: {e}")

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
        print("[!] No APKs loaded yet.")
        return

    table = []
    for row in rows:
        selected_marker = "★" if row["id"] in session.selected_apks else ""
        last_scanned = row["last_scanned"].strftime("%Y-%m-%d %H:%M:%S") if row["last_scanned"] else "Never"
        table.append([row["id"], row["file_name"], last_scanned, selected_marker])

    print(tabulate(table, headers=["ID", "APK Name", "Last Scanned", "Selected"], tablefmt="grid"))


def select_apks(identifier_str):
    identifiers = [i.strip() for i in identifier_str.split(",")]
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, file_name FROM apks")
    rows = cursor.fetchall()
    conn.close()

    selected_ids = set()
    for item in identifiers:
        for row in rows:
            if str(row["id"]) == item or row["file_name"] == item:
                selected_ids.add(row["id"])

    if selected_ids:
        session.selected_apks.update(selected_ids)
        print(f"[✓] Selected {len(selected_ids)} APK(s).")
    else:
        print("[!] No matching APKs found.")
