# db/connector.py

import mysql.connector
import json


def str_to_bool(value):
    """ Convert string to boolean. Handles 'true'/'false' strings, None, etc. """
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ['true', '1', 'yes', 'y']
    return False


def get_connection():
    with open("db/db_config.json") as f:
        config = json.load(f)
    return mysql.connector.connect(
        host=config["host"],
        user=config["user"],
        password=config["password"],
        database=config["database"]
    )

# ANSI escape code for red text
RED = "\033[91m"
RESET = "\033[0m"


def save_application_to_db(app_id, application_id, attributes, meta_data_list):
    connection = get_connection()
    try:
        cursor = connection.cursor()

        # Insert application attributes
        insert_app_query = """
            INSERT INTO application (
                app_id, application_id, name, allowTaskReparenting, allowBackup,
                allowClearUserData, allowNativeHeapPointerTagging, appCategory, backupAgent,
                backupInForeground, banner, dataExtractionRules, debuggable, description,
                enabled, enableOnBackInvokedCallback, extractNativeLibs, fullBackupContent,
                fullBackupOnly, gwpAsanMode, hasCode, hasFragileUserData, hardwareAccelerated,
                isGame, isMonitoringTool, killAfterRestore, largeHeap, label, logo,
                manageSpaceActivity, networkSecurityConfig, permission, persistent, process,
                restoreAnyVersion, requestLegacyExternalStorage, requiredAccountType,
                resizeableActivity, restrictedAccountType, supportsRtl, taskAffinity,
                testOnly, theme, uiOptions, usesCleartextTraffic, vmSafeMode
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s
            );
        """

        app_values = (
            app_id,
            application_id,
            attributes.get("android:name"),
            attributes.get("android:allowTaskReparenting"),
            str_to_bool(attributes.get("android:allowBackup")),
            str_to_bool(attributes.get("android:allowClearUserData")),
            str_to_bool(attributes.get("android:allowNativeHeapPointerTagging")),
            attributes.get("android:appCategory"),
            attributes.get("android:backupAgent"),
            str_to_bool(attributes.get("android:backupInForeground")),
            attributes.get("android:banner"),
            attributes.get("android:dataExtractionRules"),
            str_to_bool(attributes.get("android:debuggable")),
            attributes.get("android:description"),
            str_to_bool(attributes.get("android:enabled")),
            str_to_bool(attributes.get("android:enableOnBackInvokedCallback")),
            str_to_bool(attributes.get("android:extractNativeLibs")),
            attributes.get("android:fullBackupContent"),
            str_to_bool(attributes.get("android:fullBackupOnly")),
            attributes.get("android:gwpAsanMode"),
            str_to_bool(attributes.get("android:hasCode")),
            str_to_bool(attributes.get("android:hasFragileUserData")),
            str_to_bool(attributes.get("android:hardwareAccelerated")),
            str_to_bool(attributes.get("android:isGame")),
            attributes.get("android:isMonitoringTool"),
            str_to_bool(attributes.get("android:killAfterRestore")),
            str_to_bool(attributes.get("android:largeHeap")),
            attributes.get("android:label"),
            attributes.get("android:logo"),
            attributes.get("android:manageSpaceActivity"),
            attributes.get("android:networkSecurityConfig"),
            attributes.get("android:permission"),
            str_to_bool(attributes.get("android:persistent")),
            attributes.get("android:process"),
            str_to_bool(attributes.get("android:restoreAnyVersion")),
            attributes.get("android:requestLegacyExternalStorage"),
            attributes.get("android:requiredAccountType"),
            str_to_bool(attributes.get("android:resizeableActivity")),
            attributes.get("android:restrictedAccountType"),
            str_to_bool(attributes.get("android:supportsRtl")),
            attributes.get("android:taskAffinity"),
            attributes.get("android:testOnly"),
            attributes.get("android:theme"),
            attributes.get("android:uiOptions"),
            str_to_bool(attributes.get("android:usesCleartextTraffic")),
            str_to_bool(attributes.get("android:vmSafeMode"))
        )

        cursor.execute(insert_app_query, app_values)

        for meta in meta_data_list:
            cursor.execute("""
                INSERT INTO metadata (
                    app_id,
                    parent_name,
                    parent_id,
                    name,
                    resources,
                    value
                ) VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                app_id,               # integer
                "application",            # constant string as this is coming from a <service> tag
                application_id,           # unique ID for the service entry
                meta.get("android:name"),
                meta.get("android:resource"),
                meta.get("android:value")
            ))

        connection.commit()
        print("[+] Application and metadata saved successfully.")
    except Exception as e:
        connection.rollback()
        print(f"{RED}[-] Error saving application to DB: {e}{RESET}")
    finally:
        cursor.close()
        connection.close()


def save_activity(app_id, attributes, meta_data_list):
    connection = get_connection()
    try:
        cursor = connection.cursor()
        
        # Insert activity query
        insert_activity_query = """
            INSERT INTO activities (
                app_id, name, allowEmbedded, allowTaskReparenting, alwaysRetainTaskState, 
                autoRemoveFromRecents, banner, canDisplayOnRemoteDevice, clearTaskOnLaunch, 
                colorMode, configChanges, directBootAware, documentLaunchMode, enabled, 
                enableOnBackInvokedCallback, excludesFromRecents, exported, finishOnTaskLaunch, 
                hardwareAccelerated, icon, immersive, label, launchMode, lockTaskMode, 
                maxRecents, maxAspectRatio, multiprocess, noHistory, parentActivityName, 
                persistableMode, permission, process, relinquishTaskIdentity, 
                requireContentUriPermissionFromCaller, resizeableActivity, screenOrientation, 
                showForAllUsers, stateNotNeeded, supportsPictureInPicture, taskAffinity, 
                theme, uiOptions, windowSoftInputMode
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 
                      %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 
                      %s, %s, %s
            );
        """

        # Use get() with defaults for attributes that might be missing
        activity_values = (
            app_id,
            attributes.get("android:name"),
            str_to_bool(attributes.get("android:allowEmbedded")),
            str_to_bool(attributes.get("android:allowTaskReparenting")),
            str_to_bool(attributes.get("android:alwaysRetainTaskState")),
            str_to_bool(attributes.get("android:autoRemoveFromRecents")),
            attributes.get("android:banner"),
            str_to_bool(attributes.get("android:canDisplayOnRemoteDevice")),
            str_to_bool(attributes.get("android:clearTaskOnLaunch")),
            attributes.get("android:colorMode"),
            attributes.get("android:configChanges"),
            str_to_bool(attributes.get("android:directBootAware")),
            attributes.get("android:documentLaunchMode"),
            str_to_bool(attributes.get("android:enabled", "false")),
            str_to_bool(attributes.get("android:enableOnBackInvokedCallback")),
            str_to_bool(attributes.get("android:excludesFromRecents")),
            str_to_bool(attributes.get("android:exported")),
            str_to_bool(attributes.get("android:finishOnTaskLaunch")),
            str_to_bool(attributes.get("android:hardwareAccelerated")),
            attributes.get("android:icon"),
            str_to_bool(attributes.get("android:immersive")),
            attributes.get("android:label", ""),  # Default to empty string if None
            attributes.get("android:launchMode"),
            attributes.get("android:lockTaskMode"),
            attributes.get("android:maxRecents", 16),  # Default to 16
            attributes.get("android:maxAspectRatio", 1.33),  # Default to 1.33
            str_to_bool(attributes.get("android:multiprocess")),
            str_to_bool(attributes.get("android:noHistory")),
            attributes.get("android:parentActivityName"),
            attributes.get("android:persistableMode"),
            attributes.get("android:permission"),
            attributes.get("android:process"),
            str_to_bool(attributes.get("android:relinquishTaskIdentity")),
            str_to_bool(attributes.get("android:requireContentUriPermissionFromCaller")),
            str_to_bool(attributes.get("android:resizeableActivity")),
            attributes.get("android:screenOrientation"),
            str_to_bool(attributes.get("android:showForAllUsers")),
            str_to_bool(attributes.get("android:stateNotNeeded")),
            str_to_bool(attributes.get("android:supportsPictureInPicture")),
            attributes.get("android:taskAffinity"),
            attributes.get("android:theme"),
            attributes.get("android:uiOptions"),
            attributes.get("android:windowSoftInputMode")
        )

        cursor.execute(insert_activity_query, activity_values)

        activity_id = cursor.lastrowid

        for meta in meta_data_list:
            cursor.execute("""
                INSERT INTO metadata (
                    app_id,
                    parent_name,
                    parent_id,
                    name,
                    resources,
                    value
                ) VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                app_id,               # integer
                "activity",            # constant string as this is coming from a <service> tag
                activity_id,           # unique ID for the service entry
                meta.get("android:name"),
                meta.get("android:resource"),
                meta.get("android:value")
            ))

        connection.commit()
        print(f"[+] Activity '{attributes.get('android:name')}' saved successfully.")
    except Exception as e:
        print(f"{RED}[-] Error saving activity: {e}{RESET}")
    finally:
        if connection:
            connection.close()


def save_service(app_id, attributes, meta_data_list):
    connection = get_connection()
    try:
        cursor = connection.cursor()

        insert_service_query = """
            INSERT INTO services (
                app_id, name, description, directBootAware, enabled,
                exported, foregroundServiceType, isolatedProcess, label,
                permission, process, stopWithTask
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        service_values = (
            app_id,
            attributes.get("android:name"),
            attributes.get("android:description"),
            str_to_bool(attributes.get("android:directBootAware")),
            str_to_bool(attributes.get("android:enabled")),
            str_to_bool(attributes.get("android:exported")),
            attributes.get("android:foregroundServiceType"),
            str_to_bool(attributes.get("android:isolatedProcess")),
            attributes.get("android:label"),
            attributes.get("android:permission"),
            attributes.get("android:process"),
            str_to_bool(attributes.get("android:stopWithTask"))
        )

        cursor.execute(insert_service_query, service_values)
        service_id = cursor.lastrowid

        for meta in meta_data_list:
            cursor.execute("""
                INSERT INTO metadata (
                    app_id,
                    parent_name,
                    parent_id,
                    name,
                    resources,
                    value
                ) VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                app_id,               # integer
                "service",            # constant string as this is coming from a <service> tag
                service_id,           # unique ID for the service entry
                meta.get("android:name"),
                meta.get("android:resource"),
                meta.get("android:value")
            ))  

        connection.commit()
        print(f"[+] Service '{attributes.get('android:name')}' saved successfully.")

    except Exception as e:
        print(f"{RED}[-] Error saving service: {e}{RESET}")
    finally:
        if connection:
            connection.close()

def save_receiver(app_id, attributes, meta_data_list):
    connection = get_connection()
    try:
        cursor = connection.cursor()


        insert_receiver_query = """
            INSERT INTO receivers (
                app_id, name, directBootAware, enabled,
                exported, label, permission, process
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """

        receiver_values = (
            app_id,
            attributes.get("android:name"),
            str_to_bool(attributes.get("android:directBootAware")),
            str_to_bool(attributes.get("android:enabled")),
            str_to_bool(attributes.get("android:exported")),
            attributes.get("android:label"),
            attributes.get("android:permission"),
            attributes.get("android:process")
        )

        cursor.execute(insert_receiver_query, receiver_values)

        receiver_id = cursor.lastrowid

        for meta in meta_data_list:
            cursor.execute("""
                INSERT INTO metadata (
                    app_id,
                    parent_name,
                    parent_id,
                    name,
                    resources,
                    value
                ) VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                app_id,
                "receiver",
                receiver_id,
                meta.get("android:name"),
                meta.get("android:resource"),
                meta.get("android:value")
            ))

        connection.commit()
        print(f"[+] Receiver '{attributes.get('android:name')}' saved successfully.")

    except Exception as e:
        print(f"{RED}[-] Error saving receiver: {e}{RESET}")
    finally:
        if connection:
            connection.close()

import uuid

def save_provider(app_id, attributes, meta_data_list):
    connection = get_connection()
    try:
        cursor = connection.cursor()

        # Insert into providers table
        insert_provider_query = """
            INSERT INTO providers (
                app_id, authorities, enabled, directBootAware, exported,
                grantUriPermissions, initOrder, label, multiprocess,
                name, permission, process, readPermission, syncable, writePermission
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        provider_values = (
            app_id,
            attributes.get("android:authorities"),
            str_to_bool(attributes.get("android:enabled")),
            str_to_bool(attributes.get("android:directBootAware")),
            str_to_bool(attributes.get("android:exported")),
            str_to_bool(attributes.get("android:grantUriPermissions")),
            attributes.get("android:initOrder"),
            attributes.get("android:label"),
            str_to_bool(attributes.get("android:multiprocess")),
            attributes.get("android:name"),
            attributes.get("android:permission"),
            attributes.get("android:process"),
            attributes.get("android:readPermission"),
            str_to_bool(attributes.get("android:syncable")),
            attributes.get("android:writePermission")
        )

        cursor.execute(insert_provider_query, provider_values)
        provider_id = cursor.lastrowid  # Use this as parent_id in metadata

        # Insert associated meta-data
        for meta in meta_data_list:
            cursor.execute("""
                INSERT INTO metadata (
                    app_id,
                    parent_name,
                    parent_id,
                    name,
                    resources,
                    value
                ) VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                app_id,
                "provider",
                provider_id,
                meta.get("android:name"),
                meta.get("android:resource"),
                meta.get("android:value")
            ))

        connection.commit()
        print(f"[+] Provider '{attributes.get('android:name')}' saved successfully.")

    except Exception as e:
        print(f"{RED}[-] Error saving provider: {e}{RESET}")
    finally:
        if connection:
            connection.close()



