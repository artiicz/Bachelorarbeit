from PyQt6.QtWidgets import QMainWindow, QPushButton, QVBoxLayout, QWidget, QTableWidget, QTableWidgetItem, QHeaderView, QLabel, QInputDialog, QCheckBox, QGraphicsDropShadowEffect, QSpacerItem, QSizePolicy
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QKeySequence, QShortcut, QFont
from network.scanner import scan_networks, get_connected_network_info, connect_to_network, test_packet_loss

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WLAN-Sicherheits-Tool")
        self.setGeometry(100, 100, 800, 600)
        self.setMinimumSize(1000, 700)

        self.base_font_size = 10
        self.font_scale = 1.0

        # Farbenblindheits-Modus
        self.recommended_color = Qt.GlobalColor.green
        self.not_recommended_color = Qt.GlobalColor.red
        self.is_colorblind_mode = False

        # Zentrales Widget und Layout
        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        self.layout.setSpacing(10)

        # Status-Label
        self.status_label = QLabel("Drücke 'Scannen', um verfügbare Netzwerke anzuzeigen.", self)
        self.status_label.setAccessibleName("Status-Label")
        self.status_label.setAccessibleDescription("Zeigt den Status des Scans an.")
        self.layout.addWidget(self.status_label)

        # Tabelle für Ergebnisse
        self.result_table = QTableWidget(self)
        self.result_table.setTabKeyNavigation(False)
        self.result_table.setAccessibleName("Ergebnis-Tabelle")
        self.result_table.setAccessibleDescription("Zeigt eine Liste der gescannten WLAN-Netzwerke mit Empfehlungen an.")
        self.result_table.setRowCount(0)
        self.result_table.setColumnCount(4)
        self.result_table.setHorizontalHeaderLabels(["SSID", "Signal", "Sicherheit", "Empfehlung"])
        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.result_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        #self.result_table.setAlternatingRowColors(True)
        self.result_table.setSortingEnabled(True)
        self.result_table.itemClicked.connect(self.show_details)
        self.result_table.keyPressEvent = self.table_key_press_event
        self.layout.addWidget(self.result_table)

        # Details-Label
        self.details_label = QLabel("Wähle ein Netzwerk aus, um Details anzuzeigen.", self)
        self.details_label.setAccessibleName("Details-Label")
        self.details_label.setAccessibleDescription("Zeigt detaillierte Informationen über das ausgewählte Netzwerk an.")
        self.details_label.setWordWrap(True)
        self.details_label.setFocusPolicy(Qt.FocusPolicy.TabFocus)
        self.layout.addWidget(self.details_label)

        # Verbundenes Netzwerk Label
        self.connected_label = QLabel("Informationen über das verbundene Netzwerk werden nach dem Scan angezeigt.", self)
        self.connected_label.setAccessibleName("Verbundenes-Netzwerk-Label")
        self.connected_label.setAccessibleDescription("Zeigt Informationen über das aktuell verbundene WLAN-Netzwerk an.")
        self.connected_label.setFocusPolicy(Qt.FocusPolicy.TabFocus)
        self.connected_label.setWordWrap(True)
        self.layout.addWidget(self.connected_label)

        # Farbenblindheits-Modus Checkbox
        self.colorblind_checkbox = QCheckBox("Farbenblindheits-Modus aktivieren", self)
        self.colorblind_checkbox.setAccessibleName("Farbenblindheits-Checkbox")
        self.colorblind_checkbox.setAccessibleDescription("Ändert die Farben für Empfehlungen, um sie für Farbenblinde besser sichtbar zu machen.")
        self.colorblind_checkbox.stateChanged.connect(self.toggle_colorblind_mode)
        self.layout.addWidget(self.colorblind_checkbox)

        # Button-Layout
        self.button_layout = QVBoxLayout()
        self.button_layout.setSpacing(5)

        # Scan-Button
        self.scan_button = QPushButton("Netzwerke scannen", self)
        self.scan_button.setAccessibleName("Scan-Button")
        self.scan_button.setAccessibleDescription("Startet das Scannen verfügbarer WLAN-Netzwerke.")
        self.scan_button.clicked.connect(self.scan_networks)
        self.scan_button.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.scan_button.setDefault(True)
        scan_shadow = QGraphicsDropShadowEffect()
        scan_shadow.setBlurRadius(5)
        scan_shadow.setXOffset(0)
        scan_shadow.setYOffset(2)
        scan_shadow.setColor(Qt.GlobalColor.gray)
        self.scan_button.setGraphicsEffect(scan_shadow)
        self.button_layout.addWidget(self.scan_button, alignment=Qt.AlignmentFlag.AlignCenter)

        # Connect-Button
        self.connect_button = QPushButton("Mit ausgewähltem Netzwerk verbinden", self)
        self.connect_button.setAccessibleName("Connect-Button")
        self.connect_button.setAccessibleDescription("Verbindet mit dem ausgewähltem WLAN-Netzwerk, falls empfohlen.")
        self.connect_button.clicked.connect(self.connect_to_selected_network)
        connect_shadow = QGraphicsDropShadowEffect()
        connect_shadow.setBlurRadius(5)
        connect_shadow.setXOffset(0)
        connect_shadow.setYOffset(2)
        connect_shadow.setColor(Qt.GlobalColor.gray)
        self.connect_button.setGraphicsEffect(connect_shadow)
        self.connect_button.setVisible(False)

        self.button_spacer = QSpacerItem(300, 40, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.button_layout.addItem(self.button_spacer)
        self.layout.addLayout(self.button_layout)

        # Fokus-Reihenfolge setzen
        self.setTabOrder(self.result_table, self.details_label)
        self.setTabOrder(self.details_label, self.connected_label)
        self.setTabOrder(self.connected_label, self.colorblind_checkbox)
        self.setTabOrder(self.colorblind_checkbox, self.scan_button)
        self.setTabOrder(self.scan_button, self.connect_button)
        self.setTabOrder(self.connect_button, self.result_table)

        self.scan_button.setFocus()

        # Tastenkürzel für Scannen (Ctrl+S)
        self.scan_shortcut = QShortcut(QKeySequence("Ctrl+S"), self)
        self.scan_shortcut.activated.connect(self.scan_networks)

        # Tastenkürzel für Zoom (Ctrl+ und Ctrl-)
        self.zoom_in_shortcut = QShortcut(QKeySequence("Ctrl++"), self)
        self.zoom_in_shortcut.activated.connect(self.zoom_in)
        self.zoom_out_shortcut = QShortcut(QKeySequence("Ctrl+-"), self)
        self.zoom_out_shortcut.activated.connect(self.zoom_out)

        self.update_font_size()

    def update_font_size(self):
        """Aktualisiert die Schriftgröße aller UI-Elemente basierend auf dem Skalierungsfaktor."""
        scaled_size = int(self.base_font_size * self.font_scale)
        
        # Font-Objekt erstellen
        font = QFont("Arial", scaled_size)
        
        # Schriftgröße für alle Widgets setzen
        self.status_label.setFont(font)
        self.result_table.setFont(font)
        self.result_table.horizontalHeader().setFont(font)
        self.details_label.setFont(font)
        self.connected_label.setFont(font)
        self.colorblind_checkbox.setFont(font)
        self.scan_button.setFont(font)
        self.connect_button.setFont(font)

        self.status_label.setStyleSheet(f"font-size: {scaled_size}pt; color: #000000; padding: 5px;")
        self.result_table.setStyleSheet(f"""
            QTableWidget {{
                font-size: {scaled_size}pt;
                color: #000000;
                background-color: #FFFFFF;
                border: 1px solid #CCCCCC;
                gridline-color: #CCCCCC;
            }}
            QTableWidget::item {{
                padding: 5px;
            }}
            QHeaderView::section {{
                background-color: #4A90E2;
                color: #000000;
                padding: 5px;
                border: 1px solid #CCCCCC;
                font-size: {scaled_size}pt;
            }}
            QTableWidget::item:alternate {{
                background-color: #F5F5F5;
            }}
        """)

        self.details_label.setStyleSheet(f"""
            QLabel {{
                font-size: {scaled_size}pt;
                color: #333333;
                padding: 5px;
                border: 1px solid #CCCCCC;
                background-color: #F0F0F0;
            }}
            QLabel:focus {{
                border: 2px solid #003087;
                background-color: #E0E0FF;
            }}
        """)
        self.connected_label.setStyleSheet(f"""
            QLabel {{
                font-size: {scaled_size}pt;
                color: #333333;
                padding: 5px;
                border: 1px solid #CCCCCC;
                background-color: #F0F0F0;
            }}
            QLabel:focus {{
                border: 2px solid #003087;
                background-color: #E0E0FF;
            }}
        """)
        self.scan_button.setStyleSheet(f"""
            QPushButton {{
                font-size: {scaled_size}pt;
                color: #000000;
                background-color: #299FFF;
                padding: 8px;
                border-radius: 5px;
                border: none;
            }}
            QPushButton:hover {{
                background-color: #005BB5;
            }}
            QPushButton:focus {{
                border: 2px solid #003087;
            }}
        """)
        self.connect_button.setStyleSheet(f"""
            QPushButton {{
                font-size: {scaled_size}pt;
                color: #000000;
                background-color: #28A745;
                padding: 8px;
                border-radius: 5px;
                border: none;
            }}
            QPushButton:hover {{
                background-color: #218838;
            }}
            QPushButton:focus {{
                border: 2px solid #1C6D2F;
            }}
        """)
        button_min_width = int(200 * self.font_scale)
        button_connect_min_width = int(260 * self.font_scale)
        button_min_height = int(40 * self.font_scale)
        self.scan_button.setMinimumSize(button_min_width, button_min_height)
        self.connect_button.setMinimumSize(button_connect_min_width, button_min_height)

    def zoom_in(self):
        """Erhöht die Schriftgröße um 10%, maximal bis 200%."""
        if self.font_scale < 2.0:
            self.font_scale += 0.1
            self.update_font_size()
            self.status_label.setText(f"Zoom: {int(self.font_scale * 100)}%")

    def zoom_out(self):
        """Verkleinert die Schriftgröße um 10%, minimal bis 50%."""
        if self.font_scale > 0.5:
            self.font_scale -= 0.1
            self.update_font_size()
            self.status_label.setText(f"Zoom: {int(self.font_scale * 100)}%")

    def toggle_colorblind_mode(self, state):
        self.is_colorblind_mode = (state == Qt.CheckState.Checked.value)
        if self.is_colorblind_mode:
            self.recommended_color = Qt.GlobalColor.cyan
            self.not_recommended_color = Qt.GlobalColor.yellow
            self.status_label.setText("Farbenblindheits-Modus aktiviert: Empfohlene Netzwerke sind jetzt blau, nicht empfohlene gelb.")
        else:
            self.recommended_color = Qt.GlobalColor.green
            self.not_recommended_color = Qt.GlobalColor.red
            self.status_label.setText("Farbenblindheits-Modus deaktiviert: Empfohlene Netzwerke sind jetzt grün, nicht empfohlene rot.")
        # Tabelle aktualisieren, um die neuen Farben anzuzeigen
        self.update_table_colors()

    def update_table_colors(self):
        # Tabelle aktualisieren, um die Farben der Empfehlungsspalte zu setzen
        for row in range(self.result_table.rowCount()):
            recommendation = self.result_table.item(row, 3).text() if self.result_table.item(row, 3) else ""
            recommendation_item = QTableWidgetItem(recommendation)
            if recommendation == "Empfohlen":
                recommendation_item.setBackground(self.recommended_color)
            else:
                recommendation_item.setBackground(self.not_recommended_color)
            self.result_table.setItem(row, 3, recommendation_item)

    def table_key_press_event(self, event):
        """Überschreibt Tastaturevents für die Tabelle."""
        current_row = self.result_table.currentRow()
        if current_row >= 0:
            if event.key() == Qt.Key.Key_Enter or event.key() == Qt.Key.Key_Return:
                recommendation = self.result_table.item(current_row, 3).text()
                if recommendation == "Empfohlen":
                    self.connect_to_selected_network()
            elif event.key() == Qt.Key.Key_Space:
                item = self.result_table.item(current_row, 0)
                if item:
                    self.show_details(item)
        QTableWidget.keyPressEvent(self.result_table, event)

    def scan_networks(self):
        try:
            # Verfügbare Netzwerke scannen
            networks = scan_networks()
            if networks:
                self.result_table.setRowCount(0)
                # Tabelle füllen
                for row, net in enumerate(networks):
                    self.result_table.insertRow(row)
                    self.result_table.setItem(row, 0, QTableWidgetItem(net.get("ssid", "Unbekannt")))
                    signal_item = QTableWidgetItem(net.get("signal", "Unbekannt"))
                    signal_value = int(net.get("signal", "0").replace("%", "")) if net.get("signal", "Unbekannt") != "Unbekannt" else 0
                    signal_item.setData(Qt.ItemDataRole.UserRole, signal_value)
                    self.result_table.setItem(row, 1, signal_item)
                    self.result_table.setItem(row, 2, QTableWidgetItem(net.get("security", "Unbekannt")))
                    recommendation_item = QTableWidgetItem(net.get("recommendation", "Unbekannt"))
                    if net.get("recommendation") == "Empfohlen":
                        recommendation_item.setBackground(self.recommended_color)
                    else:
                        recommendation_item.setBackground(self.not_recommended_color)
                    self.result_table.setItem(row, 3, recommendation_item)
                self.status_label.setText(f"Scan abgeschlossen, {len(networks)} Netzwerke gefunden.")
                self.result_table.setFocus()
                # Connect-Button sichtbar machen, nachdem Netzwerke gescannt wurden
                self.button_layout.removeItem(self.button_spacer)  # Spacer entfernen
                self.button_layout.addWidget(self.connect_button, alignment=Qt.AlignmentFlag.AlignCenter)  # Button zentriert hinzufügen
                self.connect_button.setVisible(True)
            else:
                self.result_table.setRowCount(0)
                self.status_label.setText("Keine Netzwerke gefunden.")
                self.result_table.setAccessibleDescription("Keine Netzwerke gefunden.")
                # Connect-Button unsichtbar lassen, wenn keine Netzwerke gefunden wurden
                self.connect_button.setVisible(False)
                # Spacer wieder hinzufügen, wenn der Button unsichtbar ist
                if not self.button_layout.indexOf(self.button_spacer) >= 0:
                    self.button_layout.addItem(self.button_spacer)

            # Informationen über das verbundene Netzwerk abrufen
            connected_info = get_connected_network_info()
            if connected_info:
                ssid = connected_info.get("ssid", "Unbekannt")
                signal = connected_info.get("signal", "Unbekannt")
                receive_rate = connected_info.get("receive_rate", "Unbekannt")
                transmit_rate = connected_info.get("transmit_rate", "Unbekannt")
                channel = connected_info.get("channel", "Unbekannt")
                # Interferenz prüfen
                channel_usage = sum(1 for net in networks if net.get("channel") == channel) if networks else 0
                interference_risk = "Hoch" if channel_usage > 3 else "Niedrig"
                # Paketverlust-Test
                packet_loss = test_packet_loss()
                stability = "Stabil" if packet_loss < 10 else "Instabil"
                self.connected_label.setText(
                    f"Verbundenes Netzwerk: {ssid}\n"
                    f"Signal: {signal}\n"
                    f"Empfangsrate: {receive_rate} MBit/s\n"
                    f"Übertragungsrate: {transmit_rate} MBit/s\n"
                    f"Kanal: {channel} (Interferenzrisiko: {interference_risk})\n"
                    f"Paketverlust: {packet_loss}% (Verbindung: {stability})"
                )
            else:
                self.connected_label.setText("Nicht mit einem WLAN-Netzwerk verbunden.")
        except Exception as e:
            self.result_table.setRowCount(0)
            self.status_label.setText(f"Fehler beim Scannen: {str(e)}")
            self.result_table.setAccessibleDescription(f"Fehler beim Scannen: {str(e)}")
            # Connect-Button unsichtbar lassen, wenn ein Fehler auftritt
            self.connect_button.setVisible(False)
            # Spacer wieder hinzufügen, wenn der Button unsichtbar ist
            if not self.button_layout.indexOf(self.button_spacer) >= 0:
                self.button_layout.addItem(self.button_spacer)

    def show_details(self, item):
        row = item.row()
        ssid = self.result_table.item(row, 0).text()
        # Finde das Netzwerk in den gescannten Daten
        networks = scan_networks()
        if networks:
            for net in networks:
                if net.get("ssid") == ssid:
                    self.details_label.setText(
                        f"Details für {ssid}:\n"
                        f"Authentifizierung: {net.get('auth', 'Unbekannt')}\n"
                        f"Verschlüsselung: {net.get('encryption', 'Unbekannt')}\n"
                        f"Kanal: {net.get('channel', 'Unbekannt')}\n"
                        f"Funktyp: {net.get('funktyp', 'Unbekannt')}\n"
                        f"BSSID: {net.get('bssid', 'Unbekannt')}\n"
                        f"Empfehlungsgrund: {net.get('recommendation_reason', 'Unbekannt')}"
                    )
                    break

    def connect_to_selected_network(self):
        current_row = self.result_table.currentRow()
        if current_row == -1:
            self.status_label.setText("Bitte wähle ein Netzwerk aus.")
            return

        ssid = self.result_table.item(current_row, 0).text()
        recommendation = self.result_table.item(current_row, 3).text()

        if recommendation != "Empfohlen":
            self.status_label.setText(f"Verbindung mit {ssid} nicht empfohlen. Bitte wähle ein sicheres Netzwerk.")
            return

        # Authentifizierung und Verschlüsselung aus den gescannten Daten
        networks = scan_networks()
        auth = "WPA2PSK"
        encryption = "AES"
        if networks:
            for net in networks:
                if net.get("ssid") == ssid:
                    auth = net.get("auth", "WPA2PSK").replace("-Personal", "PSK")
                    encryption = net.get("encryption", "AES")
                    break

        # Passwort abfragen
        password, ok = QInputDialog.getText(self, "Passwort eingeben", f"Passwort für {ssid}:")
        if not ok:
            self.status_label.setText("Verbindung abgebrochen.")
            return

        try:
            result = connect_to_network(ssid, password, auth, encryption)
            self.status_label.setText(f"Erfolgreich mit {ssid} verbunden.")
            # Informationen über das verbundene Netzwerk aktualisieren
            self.scan_networks()
        except Exception as e:
            self.status_label.setText(f"Fehler beim Verbinden mit {ssid}: Falsches Passwort")

        QWidget.setTabOrder(self.result_table, self.colorblind_checkbox)
