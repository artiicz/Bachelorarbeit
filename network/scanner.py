import subprocess
import re
import os
import xml.sax.saxutils as saxutils

def scan_networks():
    try:
        # Verfügbare Netzwerke scannen
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=Bssid"],
            capture_output=True,
            text=False,
            check=True
        )
        output = result.stdout.decode("cp850", errors="replace")

        # Netzwerke parsen
        networks = []
        current_network = {}
        current_bssid = None
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("SSID"):
                if current_network:
                    networks.append(current_network)
                current_network = {"ssid": line.split(":")[1].strip()}
                current_bssid = None
            elif line.startswith("BSSID"):
                current_bssid = line.split(":", 1)[1].strip()
                if current_bssid:
                    current_network["bssid"] = current_bssid
            elif line.startswith("Signal") and current_bssid:
                signal = line.split(":")[1].strip()
                current_network["signal"] = signal if signal else "Unbekannt"
            elif line.startswith("Funktyp") and current_bssid:
                current_network["funktyp"] = line.split(":")[1].strip()
            elif line.startswith("Kanal") and current_bssid:
                channel = line.split(":")[1].strip()
                current_network["channel"] = channel if channel else "Unbekannt"
            elif line.startswith("Authentifizierung"):
                current_network["auth"] = line.split(":")[1].strip()
            elif line.startswith("Verschlüsselung"):
                current_network["encryption"] = line.split(":")[1].strip()
        if current_network:
            networks.append(current_network)
        if networks:    
            evaluate_wlan_security(networks)
        return networks if networks else None

    except subprocess.CalledProcessError as e:
        raise Exception(f"Fehler beim Scannen mit netsh: {str(e)}")
    except Exception as e:
        raise Exception(f"Fehler: {str(e)}")

def evaluate_wlan_security(networks):
    # Sicherheitsbewertung, Empfehlung und Begründung hinzufügen
        for net in networks:
            auth = net.get('auth', 'Unbekannt')
            signal = net.get('signal', 'Unbekannt')
            channel = net.get('channel', 'Unbekannt')
            signal_value = int(signal.replace("%", "")) if signal != "Unbekannt" and signal.endswith("%") else None

            # Sicherheitsbewertung
            if auth in ["WPA2-Personal", "WPA3-Personal"]:
                security = "Sicher"
                security_reason = "Sichere Verschlüsselung"
            elif auth == "Offen":
                security = "Unsicher"
                security_reason = "Keine Verschlüsselung (offen)"
            elif auth == "WEP":
                security = "Unsicher"
                security_reason = "Veraltete Verschlüsselung (WEP)"
            else:
                security = "Unbekannt"
                security_reason = "Unbekannte Verschlüsselung"

            # Signalstärke berücksichtigen
            if security == "Sicher" and signal_value is not None:
                if signal_value < 30:
                    security = "Sicher, aber schwaches Signal"
                    security_reason = "Sichere Verschlüsselung, aber schwaches Signal (< 30%)"

            # Interferenzrisiko
            channel_usage = sum(1 for n in networks if n.get("channel") == channel)
            interference_risk = "Hoch" if channel_usage > 3 else "Niedrig"
            if interference_risk == "Hoch" and security.startswith("Sicher"):
                security = f"{security}, hohe Interferenz"
                security_reason = f"{security_reason}, aber hohe Interferenz (Kanal {channel} wird von {channel_usage} Netzwerken genutzt)"

            net["security"] = security
            net["security_reason"] = security_reason

            # Empfehlung
            if security == "Sicher" and signal_value is not None and signal_value >= 50 and interference_risk == "Niedrig":
                net["recommendation"] = "Empfohlen"
                net["recommendation_reason"] = f"Sichere Verschlüsselung ({auth}), starkes Signal ({signal}), geringe Interferenz"
            else:
                net["recommendation"] = "Nicht empfohlen"
                net["recommendation_reason"] = security_reason

def get_connected_network_info():
    try:
        # Informationen über das verbundene Netzwerk abrufen
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=False,
            check=True
        )
        output = result.stdout.decode("cp850", errors="replace")

        # Informationen parsen
        connected_info = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("SSID"):
                connected_info["ssid"] = line.split(":")[1].strip()
            elif line.startswith("Signal"):
                connected_info["signal"] = line.split(":")[1].strip()
            elif line.startswith("Empfangsrate"):
                connected_info["receive_rate"] = line.split(":")[1].strip()
            elif line.startswith("Übertragungsrate"):
                connected_info["transmit_rate"] = line.split(":")[1].strip()
            elif line.startswith("Kanal"):
                connected_info["channel"] = line.split(":")[1].strip()

        return connected_info if connected_info else None
    except subprocess.CalledProcessError as e:
        raise Exception(f"Fehler beim Abrufen der Verbindungsinformationen: {str(e)}")
    except Exception as e:
        raise Exception(f"Fehler: {str(e)}")

def connect_to_network(ssid, password, auth="WPA2PSK", encryption="AES"):
    temp_file = f"{ssid}_profile.xml"
    try:
        # Bestehendes Profil löschen (falls vorhanden)
        result = subprocess.run(
            ["netsh", "wlan", "delete", "profile", f"name={ssid}"],
            capture_output=True,
            text=False,
            check=False
        )
        delete_output = result.stdout.decode("cp850", errors="replace")
        print(f"Debug: Profil löschen Ausgabe: {delete_output}")

        # Sonderzeichen im SSID und Passwort escapen
        escaped_ssid = saxutils.escape(ssid)
        escaped_password = saxutils.escape(password)

        # Authentifizierung
        if auth == "WPA3-Personal":
            auth = "WPA3PSK"
        elif auth == "WPA2-Personal":
            auth = "WPA2PSK"
        elif auth == "WPA-Personal":
            auth = "WPAPSK"

        # Verschlüsselung anpassen (CCMP → AES)
        if encryption == "CCMP":
            encryption = "AES"

        # Temporäre XML-Profil-Datei erstellen
        profile_xml = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{escaped_ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{escaped_ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>{auth}</authentication>
                <encryption>{encryption}</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{escaped_password}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>
"""
        # Temporäre Datei speichern
        print(f"Debug: Erstelle XML-Datei: {temp_file}")
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(profile_xml)
        print(f"Debug: XML-Datei erfolgreich erstellt: {temp_file}")

        # Profil hinzufügen
        result = subprocess.run(
            ["netsh", "wlan", "add", "profile", f"filename={temp_file}"],
            capture_output=True,
            text=False,
            check=True
        )
        output = result.stdout.decode("cp850", errors="replace")
        print(f"Debug: Profil hinzufügen Ausgabe: {output}")
        if "wird der schnittstelle" in output.lower() or "erfolgreich" in output.lower():
            print("Debug: Profil erfolgreich hinzugefügt")
        else:
            raise Exception(f"Fehler beim Hinzufügen des Profils: {output}")

        # Mit dem Netzwerk verbinden
        connect_cmd = ["netsh", "wlan", "connect", f"ssid={ssid}", f"name={ssid}"]
        result = subprocess.run(connect_cmd, capture_output=True, text=False, check=True)
        connect_output = result.stdout.decode("cp850", errors="replace")
        print(f"Debug: Verbindungsausgabe: {connect_output}")
        if "erfolgreich" in connect_output.lower() or "verbindung wurde erfolgreich hergestellt" in connect_output.lower():
            print("Debug: Verbindung erfolgreich hergestellt")
            return "Erfolgreich verbunden"
        else:
            raise Exception(f"Fehler beim Verbinden: {connect_output}")
    except subprocess.CalledProcessError as e:
        error_output = e.stderr.decode("cp850", errors="replace") if e.stderr else str(e)
        print(f"Debug: Fehlerausgabe: {error_output}")
        raise Exception(f"Fehler beim Verbinden mit {ssid}: {error_output}")
    except Exception as e:
        print(f"Debug: Allgemeiner Fehler: {str(e)}")
        raise Exception(f"Fehler: {str(e)}")
    finally:
        # Sicherstellen, dass die temporäre Datei gelöscht wird, auch bei Fehlern
        if os.path.exists(temp_file):
            print(f"Debug: Lösche temporäre Datei: {temp_file}")
            os.remove(temp_file)

def test_packet_loss():
    try:
        # Ping-Test durchführen (4 Pings an Google DNS)
        result = subprocess.run(
            ["ping", "-n", "4", "8.8.8.8"],
            capture_output=True,
            text=False,
            check=True
        )

        output = result.stdout.decode("cp850", errors="replace")

        # Paketverlust parsen
        for line in output.splitlines():
            if "Verlust" in line:
                loss = re.search(r"(\d+)% Verlust", line)
                if loss:
                    return int(loss.group(1))
        return 0
    except subprocess.CalledProcessError as e:
        raise Exception(f"Fehler beim Paketverlust-Test: {str(e)}")
    except Exception as e:
        raise Exception(f"Fehler: {str(e)}")