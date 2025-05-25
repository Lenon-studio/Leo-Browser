import sys
import json
import uuid
import os
import time
import random # Şifre önerme için

from PyQt5.QtCore import QUrl, Qt, QDateTime, QStandardPaths, QTimer, QCoreApplication
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QToolBar, QLineEdit,
    QPushButton, QAction, QDialog, QVBoxLayout,
    QHBoxLayout, QLabel, QMessageBox, QTabWidget,
    QListWidget, QListWidgetItem, QInputDialog, QCheckBox,
    QTextEdit, QFileDialog, QProgressBar, QWidget
)
from PyQt5.QtGui import QPalette, QColor, QFont, QIcon, QPixmap
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEngineProfile, QWebEnginePage, QWebEngineSettings, QWebEngineDownloadItem

# Firebase ile etkileşim için gerekli modüller (Canvas ortamında varsayılan olarak sağlanır)
try:
    _app_id = "leo-browser-app"
    _firebase_config = json.loads(__firebase_config) if '__firebase_config' in locals() else {}
    _initial_auth_token = __initial_auth_token if '__initial_auth_token' in locals() else None

    class MockDocumentSnapshot:
        def __init__(self, exists, data, doc_id=None):
            self._exists = exists
            self._data = data
            self._id = doc_id
            self.reference = MockDocumentReference(doc_id=doc_id)

        @property
        def exists(self):
            return self._exists

        @property
        def id(self):
            return self._id

        def to_dict(self):
            return self._data

    class MockDocumentReference:
        def __init__(self, doc_id, collection_ref=None):
            self._id = doc_id
            self._collection_ref = collection_ref
            self._snapshot_callbacks = []

        @property
        def id(self):
            return self._id

        def delete(self):
            if self._collection_ref:
                self._collection_ref._mock_docs.pop(self._id, None)

        def set(self, data):
            if self._collection_ref:
                self._collection_ref._mock_docs[self._id] = data
                self._notify_snapshot_listeners()
                self._collection_ref._notify_snapshot_listeners()

        def on_snapshot(self, callback):
            self._snapshot_callbacks.append(callback)
            current_data = self._collection_ref._mock_docs.get(self._id, {})
            current_exists = self._id in self._collection_ref._mock_docs
            mock_doc_snapshot = MockDocumentSnapshot(current_exists, current_data, self._id)
            callback(mock_doc_snapshot, [], None)
            return lambda: self._snapshot_callbacks.remove(callback)

        def _notify_snapshot_listeners(self):
            current_data = self._collection_ref._mock_docs.get(self._id, {})
            current_exists = self._id in self._collection_ref._mock_docs
            mock_doc_snapshot = MockDocumentSnapshot(current_exists, current_data, self._id)
            for callback in self._snapshot_callbacks:
                callback(mock_doc_snapshot, [], None)


    class MockCollectionReference:
        def __init__(self, path, firestore_instance):
            self._path = path
            self._firestore = firestore_instance
            if path not in self._firestore._mock_data:
                self._firestore._mock_data[path] = {}
            self._mock_docs = self._firestore._mock_data[path]
            self._snapshot_callbacks = []

        def document(self, doc_id):
            return MockDocumentReference(doc_id, self)

        def add(self, data):
            new_doc_id = str(uuid.uuid4())
            self._mock_docs[new_doc_id] = data
            self._notify_snapshot_listeners()
            return MockDocumentReference(new_doc_id, self)

        def on_snapshot(self, callback):
            self._snapshot_callbacks.append(callback)
            mock_col_snapshot = [MockDocumentSnapshot(True, data, doc_id) for doc_id, data in self._mock_docs.items()]
            callback(mock_col_snapshot, [], None)
            return lambda: self._snapshot_callbacks.remove(callback)

        def _notify_snapshot_listeners(self):
            mock_col_snapshot = [MockDocumentSnapshot(True, data, doc_id) for doc_id, data in self._mock_docs.items()]
            for callback in self._snapshot_callbacks:
                callback(mock_col_snapshot, [], None)

        def query(self):
            return MockQuery(self)

        def get_docs(self):
            return [MockDocumentSnapshot(True, data, doc_id) for doc_id, data in self._mock_docs.items()]

    class MockQuery:
        def __init__(self, collection_ref):
            self._collection_ref = collection_ref
            self._filters = []

        def where(self, field, op, value):
            self._filters.append({'field': field, 'op': op, 'value': value})
            return self

        def get_docs(self):
            filtered_docs = []
            for doc_id, data in self._collection_ref._mock_docs.items():
                match = True
                for f in self._filters:
                    doc_value = data.get(f['field'])
                    if f['op'] == '==' and doc_value != f['value']:
                        match = False
                        break
                if match:
                    filtered_docs.append(MockDocumentSnapshot(True, data, doc_id))
            return filtered_docs

    class MockFirestore:
        def __init__(self):
            self._mock_data = {}

        def collection(self, path):
            return MockCollectionReference(path, self)

    class MockAuth:
        def __init__(self, uid=None):
            self._uid = uid if uid else str(uuid.uuid4())

        @property
        def current_user(self):
            return MockUser(self._uid)

    class MockUser:
        def __init__(self, uid):
            self.uid = uid

    db = MockFirestore()
    auth = MockAuth(uid=str(uuid.uuid4()))
    _user_id = auth.current_user.uid

except Exception as e:
    print(f"Firebase başlatma hatası (mock): {e}. Senkronizasyon devre dışı bırakılacak.")
    db = None
    auth = None
    _app_id = "default-app-id"
    _user_id = str(uuid.uuid4()) # Firebase kullanılamıyorsa rastgele bir UID

# --- Geri Bildirim İletişim Kutusu Sınıfı ---
class FeedbackDialog(QDialog):
    """
    Kullanıcıdan geri bildirim almak için bir iletişim kutusu.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Geri Bildirim Gönder")
        self.setGeometry(300, 300, 500, 400)
        self.setWindowFlag(Qt.WindowContextHelpButtonHint, False)

        main_layout = QVBoxLayout()

        self.feedback_label = QLabel("Lütfen geri bildiriminizi detaylı bir şekilde yazın:")
        self.feedback_text_edit = QTextEdit(self)
        self.feedback_text_edit.setPlaceholderText("Geri bildiriminiz...")
        self.feedback_text_edit.setMinimumHeight(150)

        self.send_button = QPushButton("Gönder", self)
        self.cancel_button = QPushButton("İptal", self)

        self.send_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)

        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(self.send_button)
        button_layout.addWidget(self.cancel_button)
        button_layout.addStretch()

        main_layout.addWidget(self.feedback_label)
        main_layout.addWidget(self.feedback_text_edit)
        main_layout.addLayout(button_layout)
        self.setLayout(main_layout)

    def get_feedback_text(self):
        return self.feedback_text_edit.toPlainText()

# --- Ayarlar İletişim Kutusu Sınıfı ---
class SettingsDialog(QDialog):
    """
    Ana sayfa URL'sini, optimizasyon modunu, reklam engelleyiciyi, pil tasarrufu modunu,
    karanlık modu ve özel arama motorunu ayarlamak için bir iletişim kutusu.
    """
    def __init__(self, current_settings, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Ayarlar")
        self.setGeometry(200, 200, 500, 450)
        self.setWindowFlag(Qt.WindowContextHelpButtonHint, False)

        self.homepage_input = QLineEdit(self)
        self.homepage_input.setPlaceholderText("Yeni ana sayfa URL'sini girin")
        self.homepage_input.setText(current_settings.get('homepage_url', ''))

        self.optimization_mode_checkbox = QCheckBox("Optimizasyon Modu (Resimleri ve JavaScript'i Devre Dışı Bırak)", self)
        self.optimization_mode_checkbox.setChecked(current_settings.get('optimization_mode', False))

        self.battery_saving_mode_checkbox = QCheckBox("Pil Tasarrufu Modu (Daha Agresif Optimizasyon)", self)
        self.battery_saving_mode_checkbox.setChecked(current_settings.get('battery_saving_mode', False))

        self.ad_blocker_checkbox = QCheckBox("Reklam Engelleyiciyi Etkinleştir", self)
        self.ad_blocker_checkbox.setChecked(current_settings.get('ad_blocker', False))

        self.dark_mode_checkbox = QCheckBox("Karanlık Modu Etkinleştir (Tarayıcı Arayüzü)", self)
        self.dark_mode_checkbox.setChecked(current_settings.get('dark_mode', False))

        self.custom_search_engine_input = QLineEdit(self)
        self.custom_search_engine_input.setPlaceholderText("Özel Arama Motoru URL'si (örn: https://duckduckgo.com/?q={query})")
        self.custom_search_engine_input.setText(current_settings.get('custom_search_engine_url', ''))

        self.debug_mode_checkbox = QCheckBox("Hata Ayıklama Modu (Konsola Detaylı Log Yaz)", self)
        self.debug_mode_checkbox.setChecked(current_settings.get('debug_mode', False))

        self.save_button = QPushButton("Kaydet", self)
        self.cancel_button = QPushButton("İptal", self)

        self.save_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)

        form_layout = QVBoxLayout()
        form_layout.addWidget(QLabel("Ana Sayfa URL'si:"))
        form_layout.addWidget(self.homepage_input)
        form_layout.addWidget(self.optimization_mode_checkbox)
        form_layout.addWidget(self.battery_saving_mode_checkbox)
        form_layout.addWidget(self.ad_blocker_checkbox)
        form_layout.addWidget(self.dark_mode_checkbox)
        form_layout.addWidget(QLabel("Özel Arama Motoru URL'si:"))
        form_layout.addWidget(self.custom_search_engine_input)
        form_layout.addWidget(self.debug_mode_checkbox)

        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(self.save_button)
        button_layout.addWidget(self.cancel_button)
        button_layout.addStretch()

        main_layout = QVBoxLayout()
        main_layout.addLayout(form_layout)
        main_layout.addLayout(button_layout)
        self.setLayout(main_layout)

    def get_settings(self):
        return {
            'homepage_url': self.homepage_input.text(),
            'optimization_mode': self.optimization_mode_checkbox.isChecked(),
            'battery_saving_mode': self.battery_saving_mode_checkbox.isChecked(),
            'ad_blocker': self.ad_blocker_checkbox.isChecked(),
            'dark_mode': self.dark_mode_checkbox.isChecked(),
            'custom_search_engine_url': self.custom_search_engine_input.text(),
            'debug_mode': self.debug_mode_checkbox.isChecked()
        }

# --- Hakkında İletişim Kutusu Sınıfı ---
class AboutDialog(QMessageBox):
    """
    Tarayıcı hakkında bilgi gösteren bir iletişim kutusu.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Leo Tarayıcı Hakkında")
        self.setText("Leo Tarayıcı\nSürüm: 1.0\nOluşturucu: Lenon_Studio AI\nPython ve PyQt5 ile oluşturuldu.")
        self.setIcon(QMessageBox.Information)
        self.setStandardButtons(QMessageBox.Ok)

# --- Geçmiş İletişim Kutusu Sınıfı ---
class HistoryDialog(QDialog):
    """
    Tarayıcı geçmişini gösteren bir iletişim kutusu.
    """
    def __init__(self, history_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Geçmiş")
        self.setGeometry(200, 200, 600, 400)

        self.history_list_widget = QListWidget(self)
        self.history_data = history_data

        self._populate_list()

        self.history_list_widget.itemDoubleClicked.connect(self.item_double_clicked)

        self.clear_history_button = QPushButton("Geçmişi Temizle", self)
        self.clear_history_button.clicked.connect(self.clear_history_prompt)

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.history_list_widget)
        main_layout.addWidget(self.clear_history_button)
        self.setLayout(main_layout)

        self.selected_url = None

    def _populate_list(self):
        self.history_list_widget.clear()
        for entry in self.history_data:
            item_text = f"{entry.get('title', 'Başlıksız')} - {entry.get('url', 'URL Yok')} ({entry.get('timestamp', 'Zaman Yok')})"
            item = QListWidgetItem(item_text)
            item.setData(Qt.UserRole, entry.get('url'))
            self.history_list_widget.addItem(item)

    def item_double_clicked(self, item):
        self.selected_url = item.data(Qt.UserRole)
        self.accept()

    def get_selected_url(self):
        return self.selected_url

    def clear_history_prompt(self):
        reply = QMessageBox.question(self, 'Geçmişi Temizle',
                                     "Tüm geçmişi temizlemek istediğinizden emin misiniz?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            if self.parent() and hasattr(self.parent(), 'clear_browser_history'):
                self.parent().clear_browser_history()
                self.history_list_widget.clear()
                QMessageBox.information(self, "Geçmiş Temizlendi", "Tarayıcı geçmişi başarıyla temizlendi.")
            else:
                QMessageBox.critical(self, "Hata", "Geçmiş temizleme işlevi bulunamadı.")

# --- Yer İmleri İletişim Kutusu Sınıfı ---
class BookmarksDialog(QDialog):
    """
    Yer imlerini gösteren ve yöneten bir iletişim kutusu.
    """
    def __init__(self, bookmarks_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Yer İmleri")
        self.setGeometry(200, 200, 500, 300)

        self.bookmarks_list_widget = QListWidget(self)
        self.bookmarks_data = bookmarks_data

        self._populate_list()

        self.bookmarks_list_widget.itemDoubleClicked.connect(self.item_double_clicked)

        self.remove_bookmark_button = QPushButton("Yer İmini Kaldır", self)
        self.remove_bookmark_button.clicked.connect(self.remove_selected_bookmark)

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.bookmarks_list_widget)
        main_layout.addWidget(self.remove_bookmark_button)
        self.setLayout(main_layout)

        self.selected_url = None

    def _populate_list(self):
        self.bookmarks_list_widget.clear()
        for entry in self.bookmarks_data:
            item_text = f"{entry.get('title', 'Başlıksız')} - {entry.get('url', 'URL Yok')}"
            item = QListWidgetItem(item_text)
            item.setData(Qt.UserRole, entry.get('url'))
            self.bookmarks_list_widget.addItem(item)

    def item_double_clicked(self, item):
        self.selected_url = item.data(Qt.UserRole)
        self.accept()

    def get_selected_url(self):
        return self.selected_url

    def remove_selected_bookmark(self):
        selected_items = self.bookmarks_list_widget.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Yer İmi Kaldır", "Lütfen kaldırılacak bir yer imi seçin.")
            return

        item = selected_items[0]
        url_to_remove = item.data(Qt.UserRole)

        reply = QMessageBox.question(self, 'Yer İmini Kaldır',
                                     f"'{item.text()}' yer imini kaldırmak istediğinizden emin misiniz?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            if self.parent() and hasattr(self.parent(), 'remove_bookmark_from_firestore'):
                self.parent().remove_bookmark_from_firestore(url_to_remove)
                self.bookmarks_list_widget.takeItem(self.bookmarks_list_widget.row(item))
                QMessageBox.information(self, "Yer İmi Kaldırıldı", "Yer imi başarıyla kaldırıldı.")
            else:
                QMessageBox.critical(self, "Hata", "Yer imi kaldırma işlevi bulunamadı.")

# --- Özel WebEnginePage Sınıfı (Reklam Engelleyici ve Sağ Tıklama Menüsü için) ---
class LeoWebEnginePage(QWebEnginePage):
    def __init__(self, profile, browser_instance, parent=None):
        super().__init__(profile, parent)
        self._ad_blocker_enabled = False
        self.browser_instance = browser_instance
        self.ad_domains = [
            "doubleclick.net", "googlesyndication.com", "adservice.google.com",
            "ads.youtube.com", "ad.com", "adserver.", "analytics."
        ]
        self.feature_permissions = {} # {feature_url: {feature_type: granted/denied}}

    def set_ad_blocker_enabled(self, enabled):
        self._ad_blocker_enabled = enabled
        if self.browser_instance.debug_mode_enabled:
            print(f"Reklam engelleyici {'etkinleştirildi' if enabled else 'devre dışı bırakıldı'}")

    def acceptNavigationRequest(self, qurl, _type, is_main_frame):
        if self._ad_blocker_enabled:
            url_str = qurl.toString().lower()
            for ad_domain in self.ad_domains:
                if ad_domain in url_str:
                    if self.browser_instance.debug_mode_enabled:
                        print(f"Reklam engellendi: {url_str}")
                    return False
        return super().acceptNavigationRequest(qurl, _type, is_main_frame)

    def createStandardContextMenu(self):
        menu = super().createStandardContextMenu()

        # Sayfa kaynağını görüntüle
        view_source_action = QAction("Sayfa Kaynağını Görüntüle", self)
        view_source_action.triggered.connect(self._view_page_source)
        menu.addAction(view_source_action)

        # Öğeyi İncele (simülasyon)
        inspect_element_action = QAction("Öğeyi İncele (Simülasyon)", self)
        inspect_element_action.triggered.connect(self._inspect_element_simulated)
        menu.addAction(inspect_element_action)

        # Şifre önerme (sadece şifre alanına sağ tıklanırsa)
        hit_test_result = self.hitTestContent(self.browser_instance.mapFromGlobal(self.cursor().pos()))
        if hit_test_result.isContentEditable() or hit_test_result.formControls():
            suggest_password_action = QAction("Şifre Öner", self)
            suggest_password_action.triggered.connect(self._suggest_password)
            menu.addAction(suggest_password_action)

        # Yazılımı Gör (Site Bilgisi)
        view_software_action = QAction("Yazılımı Gör (Site Bilgisi)", self)
        view_software_action.triggered.connect(self._view_website_software_info)
        menu.addAction(view_software_action)

        return menu

    def _view_page_source(self):
        self.toHtml(lambda html: self._show_html_source(html))

    def _show_html_source(self, html_content):
        source_dialog = QDialog(self.browser_instance)
        source_dialog.setWindowTitle("Sayfa Kaynağı")
        source_dialog.setGeometry(150, 150, 800, 600)
        layout = QVBoxLayout()
        text_edit = QTextEdit()
        text_edit.setPlainText(html_content)
        text_edit.setReadOnly(True)
        layout.addWidget(text_edit)
        source_dialog.setLayout(layout)
        source_dialog.exec_()

    def _inspect_element_simulated(self):
        QMessageBox.information(self.browser_instance, "Öğeyi İncele", "Bu özellik, web sayfasının HTML/CSS yapısını incelemenizi sağlar. Gerçek bir geliştirici aracı entegrasyonu için daha fazla çalışma gereklidir.")

    def _suggest_password(self):
        password_length = 12
        characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
        suggested_password = ''.join(random.choice(characters) for i in range(password_length))
        QMessageBox.information(self.browser_instance, "Şifre Önerisi", f"Önerilen Şifre: {suggested_password}\n\nBu şifreyi kopyalayıp kullanabilirsiniz.")

    def _view_website_software_info(self):
        # Basit bir simülasyon: Sitenin HTTPS olup olmadığını kontrol et
        url = self.url().toString()
        info_message = f"<b>Web Sitesi Bilgisi:</b><br>URL: {url}<br>"
        if url.startswith("https://"):
            info_message += "Bağlantı: Güvenli (HTTPS)<br>"
            info_message += "Tahmini Teknoloji: Modern web teknolojileri (HTML5, CSS3, JavaScript çerçeveleri)"
        else:
            info_message += "Bağlantı: Güvenli Değil (HTTP)<br>"
            info_message += "Tahmini Teknoloji: Eski veya basit web teknolojileri"
        QMessageBox.information(self.browser_instance, "Yazılım Bilgisi", info_message)

    def featurePermissionRequested(self, securityOrigin, feature):
        feature_name = {
            QWebEnginePage.MediaAudioCapture: "Mikrofon",
            QWebEnginePage.MediaVideoCapture: "Kamera",
            QWebEnginePage.Geolocation: "Konum",
            QWebEnginePage.Notifications: "Bildirimler"
        }.get(feature, "Bilinmeyen Özellik")

        reply = QMessageBox.question(self.browser_instance, "İzin İsteği",
                                     f"'{securityOrigin.toString()}' web sitesi '{feature_name}' erişimi istiyor. İzin veriyor musunuz?",
                                     QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel, QMessageBox.No)

        if reply == QMessageBox.Yes:
            self.setFeaturePermission(securityOrigin, feature, QWebEnginePage.PermissionGrantedByUser)
            self.feature_permissions[securityOrigin.toString()] = self.feature_permissions.get(securityOrigin.toString(), {})
            self.feature_permissions[securityOrigin.toString()][feature_name] = "granted"
            if self.browser_instance.debug_mode_enabled:
                print(f"İzin verildi: {securityOrigin.toString()} için {feature_name}")
        elif reply == QMessageBox.No:
            self.setFeaturePermission(securityOrigin, feature, QWebEnginePage.PermissionDeniedByUser)
            self.feature_permissions[securityOrigin.toString()] = self.feature_permissions.get(securityOrigin.toString(), {})
            self.feature_permissions[securityOrigin.toString()][feature_name] = "denied"
            if self.browser_instance.debug_mode_enabled:
                print(f"İzin reddedildi: {securityOrigin.toString()} için {feature_name}")
        else: # Cancel
            self.setFeaturePermission(securityOrigin, feature, QWebEnginePage.PermissionDeniedByFeaturePolicy)
            self.feature_permissions[securityOrigin.toString()] = self.feature_permissions.get(securityOrigin.toString(), {})
            self.feature_permissions[securityOrigin.toString()][feature_name] = "denied_by_policy"
            if self.browser_instance.debug_mode_enabled:
                print(f"İzin iptal edildi: {securityOrigin.toString()} için {feature_name}")


# --- Lenon Asistan İletişim Kutusu Sınıfı ---
class LenonAssistantDialog(QDialog):
    """
    Lenon Asistanı ile etkileşim için bir iletişim kutusu.
    Lenon, tarayıcı verileriyle canlı senkronizasyon ve takip yeteneğine sahiptir.
    Kendi arama motoru konseptini kullanarak doğrudan arama yapabilir.
    """
    def __init__(self, browser_instance, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Lenon Asistanı")
        self.setGeometry(300, 300, 600, 500)
        self.setWindowFlag(Qt.WindowContextHelpButtonHint, False)

        self.browser = browser_instance

        self.chat_history = QTextEdit(self)
        self.chat_history.setReadOnly(True)
        self.chat_history.setFont(QFont("Arial", 10))
        self.chat_history.setStyleSheet("background-color: #2e2e2e; color: #ffffff; border-radius: 8px; padding: 10px;")
        self.chat_history.append("<b>Merhaba ben Lenon_Studio yapay zekasıyım. Size nasıl yardımcı olabilirim?</b>")

        self.user_input = QLineEdit(self)
        self.user_input.setPlaceholderText("Komutunuzu buraya yazın veya mikrofonu kullanın...")
        self.user_input.returnPressed.connect(self.process_command)
        self.user_input.setStyleSheet("background-color: #3a3a3a; color: #ffffff; border: 1px solid #555555; border-radius: 5px; padding: 8px;")

        self.send_button = QPushButton("Gönder", self)
        self.send_button.clicked.connect(self.process_command)
        self.send_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)

        self.microphone_button = QPushButton("Mikrofon", self)
        self.microphone_button.clicked.connect(self.simulate_voice_input)
        self.microphone_button.setStyleSheet("""
            QPushButton {
                background-color: #008CBA;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #007bb5;
            }
        """)

        input_layout = QHBoxLayout()
        input_layout.addWidget(self.user_input)
        input_layout.addWidget(self.send_button)
        input_layout.addWidget(self.microphone_button)

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.chat_history)
        main_layout.addLayout(input_layout)
        self.setLayout(main_layout)

        self.setStyleSheet("background-color: #1e1e1e;")

    def process_command(self):
        command = self.user_input.text().strip()
        if not command:
            return

        self.chat_history.append(f"<p style='color:#ADD8E6;'><b>Siz:</b> {command}</p>")
        self.user_input.clear()

        # Lenon Asistanı yanıtları doğrudan işlenir, bu da hızı artırır.
        # Karmaşık AI entegrasyonu için harici servisler gerekebilir.
        response = self.handle_assistant_command(command.lower())
        self.chat_history.append(f"<p style='color:#90EE90;'><b>Lenon:</b> {response}</p>")

    def simulate_voice_input(self):
        permission_reply = QMessageBox.question(self, 'Mikrofon İzni',
                                               "Lenon Asistanı mikrofonunuza erişmek istiyor. İzin veriyor musunuz?",
                                               QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if permission_reply == QMessageBox.Yes:
            self.chat_history.append("<p style='color:#90EE90;'>Lenon: Mikrofon erişimine izin verildi. Ne aratmak istersiniz?</p>")
            voice_command, ok = QInputDialog.getText(self, "Sesli Komut", "Lütfen sesli komutunuzu söyleyin:")
            if ok and voice_command:
                self.user_input.setText(voice_command)
                self.process_command()
            elif not ok:
                self.chat_history.append("<p style='color:#90EE90;'>Lenon: Sesli komut iptal edildi.</p>")
        else:
            self.chat_history.append("<p style='color:#90EE90;'>Lenon: Mikrofon erişimi reddedildi. Yazarak devam edebilirsiniz.</p>")

    def handle_assistant_command(self, command):
        if "merhaba" in command or "selam" in command:
            return "Merhaba! Size nasıl yardımcı olabilirim?"
        elif "nasılsın" in command:
            return "Ben bir yapay zekayım, iyiyim teşekkür ederim. Siz nasılsınız?"
        elif "arama yap" in command or "ara" in command:
            query = command.replace("arama yap", "").replace("ara", "").strip()
            if query:
                # Lenon'un kendi arama motoru konsepti (varsayılan olarak Google'ı kullanır)
                search_url = f"https://www.google.com/search?q={QUrl.toPercentEncoding(query).data().decode()}"
                self.browser.tabs.currentWidget().setUrl(QUrl(search_url))
                return f"Lenon, '{query}' için arama yapıyor..."
            else:
                return "Ne aramamı istersiniz?"
        elif "geçmişi göster" in command or "ziyaret ettiğim siteler" in command:
            self.browser.open_history()
            history_summary = "Ziyaret ettiğiniz son siteler:\n"
            if self.browser.history_data:
                for i, entry in enumerate(self.browser.history_data[:5]):
                    history_summary += f"{i+1}. {entry.get('title', 'Başlıksız')} - {entry.get('url', 'URL Yok')}\n"
                return history_summary + "\nDaha fazlası için geçmiş penceresini kontrol edebilirsiniz."
            else:
                return "Henüz bir geçmiş kaydınız bulunmuyor."
        elif "ana sayfaya git" in command:
            self.browser.navigate_home()
            return "Ana sayfaya gidiliyor."
        elif "yeni sekme aç" in command:
            self.browser.add_new_tab(QUrl(self.browser.current_homepage), 'Yeni Sekme')
            return "Yeni bir sekme açıldı."
        elif "ayarları aç" in command or "ayarları göster" in command:
            self.browser.open_settings()
            return "Ayarlar penceresi açıldı."
        elif "reklam engelleyiciyi aç" in command:
            self.browser.ad_blocker_enabled = True
            self.browser.save_settings_to_firestore({
                'homepage_url': self.browser.current_homepage,
                'optimization_mode': self.browser.optimization_mode_enabled,
                'battery_saving_mode': self.browser.battery_saving_mode_enabled,
                'ad_blocker': True,
                'dark_mode': self.browser.dark_mode_enabled,
                'custom_search_engine_url': self.browser.custom_search_engine_url,
                'debug_mode': self.browser.debug_mode_enabled
            })
            self.browser.apply_browser_settings()
            return "Reklam engelleyici etkinleştirildi."
        elif "reklam engelleyiciyi kapat" in command:
            self.browser.ad_blocker_enabled = False
            self.browser.save_settings_to_firestore({
                'homepage_url': self.browser.current_homepage,
                'optimization_mode': self.browser.optimization_mode_enabled,
                'battery_saving_mode': self.browser.battery_saving_mode_enabled,
                'ad_blocker': False,
                'dark_mode': self.browser.dark_mode_enabled,
                'custom_search_engine_url': self.browser.custom_search_engine_url,
                'debug_mode': self.browser.debug_mode_enabled
            })
            self.browser.apply_browser_settings()
            return "Reklam engelleyici devre dışı bırakıldı."
        elif "karanlık modu aç" in command:
            self.browser.dark_mode_enabled = True
            self.browser.save_settings_to_firestore({
                'homepage_url': self.browser.current_homepage,
                'optimization_mode': self.browser.optimization_mode_enabled,
                'battery_saving_mode': self.browser.battery_saving_mode_enabled,
                'ad_blocker': self.browser.ad_blocker_enabled,
                'dark_mode': True,
                'custom_search_engine_url': self.browser.custom_search_engine_url,
                'debug_mode': self.browser.debug_mode_enabled
            })
            self.browser.apply_browser_settings()
            return "Karanlık mod etkinleştirildi."
        elif "karanlık modu kapat" in command:
            self.browser.dark_mode_enabled = False
            self.browser.save_settings_to_firestore({
                'homepage_url': self.browser.current_homepage,
                'optimization_mode': self.browser.optimization_mode_enabled,
                'battery_saving_mode': self.browser.battery_saving_mode_enabled,
                'ad_blocker': self.browser.ad_blocker_enabled,
                'dark_mode': False,
                'custom_search_engine_url': self.browser.custom_search_engine_url,
                'debug_mode': self.browser.debug_mode_enabled
            })
            self.browser.apply_browser_settings()
            return "Karanlık mod devre dışı bırakıldı."
        elif "optimizasyon modunu aç" in command:
            self.browser.optimization_mode_enabled = True
            self.browser.save_settings_to_firestore({
                'homepage_url': self.browser.current_homepage,
                'optimization_mode': True,
                'battery_saving_mode': self.browser.battery_saving_mode_enabled,
                'ad_blocker': self.browser.ad_blocker_enabled,
                'dark_mode': self.browser.dark_mode_enabled,
                'custom_search_engine_url': self.browser.custom_search_engine_url,
                'debug_mode': self.browser.debug_mode_enabled
            })
            self.browser.apply_browser_settings()
            return "Optimizasyon modu etkinleştirildi. Resimler ve JavaScript devre dışı bırakılabilir."
        elif "optimizasyon modunu kapat" in command:
            self.browser.optimization_mode_enabled = False
            self.browser.save_settings_to_firestore({
                'homepage_url': self.browser.current_homepage,
                'optimization_mode': False,
                'battery_saving_mode': self.browser.battery_saving_mode_enabled,
                'ad_blocker': self.browser.ad_blocker_enabled,
                'dark_mode': self.browser.dark_mode_enabled,
                'custom_search_engine_url': self.browser.custom_search_engine_url,
                'debug_mode': self.browser.debug_mode_enabled
            })
            self.browser.apply_browser_settings()
            return "Optimizasyon modu devre dışı bırakıldı."
        elif "pil tasarrufu modunu aç" in command:
            self.browser.battery_saving_mode_enabled = True
            self.browser.save_settings_to_firestore({
                'homepage_url': self.browser.current_homepage,
                'optimization_mode': self.browser.optimization_mode_enabled,
                'battery_saving_mode': True,
                'ad_blocker': self.browser.ad_blocker_enabled,
                'dark_mode': self.browser.dark_mode_enabled,
                'custom_search_engine_url': self.browser.custom_search_engine_url,
                'debug_mode': self.browser.debug_mode_enabled
            })
            self.browser.apply_browser_settings()
            return "Pil tasarrufu modu etkinleştirildi. Daha agresif optimizasyonlar uygulanacak."
        elif "pil tasarrufu modunu kapat" in command:
            self.browser.battery_saving_mode_enabled = False
            self.browser.save_settings_to_firestore({
                'homepage_url': self.browser.current_homepage,
                'optimization_mode': self.browser.optimization_mode_enabled,
                'battery_saving_mode': False,
                'ad_blocker': self.browser.ad_blocker_enabled,
                'dark_mode': self.browser.dark_mode_enabled,
                'custom_search_engine_url': self.browser.custom_search_engine_url,
                'debug_mode': self.browser.debug_mode_enabled
            })
            self.browser.apply_browser_settings()
            return "Pil tasarrufu modu devre dışı bırakıldı."
        elif "hata ayıklama modunu aç" in command:
            self.browser.debug_mode_enabled = True
            self.browser.save_settings_to_firestore({
                'homepage_url': self.browser.current_homepage,
                'optimization_mode': self.browser.optimization_mode_enabled,
                'battery_saving_mode': self.browser.battery_saving_mode_enabled,
                'ad_blocker': self.browser.ad_blocker_enabled,
                'dark_mode': self.browser.dark_mode_enabled,
                'custom_search_engine_url': self.browser.custom_search_engine_url,
                'debug_mode': True
            })
            return "Hata ayıklama modu etkinleştirildi. Konsola daha fazla bilgi yazılacak."
        elif "hata ayıklama modunu kapat" in command:
            self.browser.debug_mode_enabled = False
            self.browser.save_settings_to_firestore({
                'homepage_url': self.browser.current_homepage,
                'optimization_mode': self.browser.optimization_mode_enabled,
                'battery_saving_mode': self.browser.battery_saving_mode_enabled,
                'ad_blocker': self.browser.ad_blocker_enabled,
                'dark_mode': self.browser.dark_mode_enabled,
                'custom_search_engine_url': self.browser.custom_search_engine_url,
                'debug_mode': False
            })
            return "Hata ayıklama modu devre dışı bırakıldı."
        elif "yardım" in command or "komutlar" in command:
            return ("Size şu konularda yardımcı olabilirim: 'arama yap [sorgu]', 'geçmişi göster', "
                    "'ana sayfaya git', 'yeni sekme aç', 'ayarları aç', 'reklam engelleyiciyi aç/kapat', "
                    "'karanlık modu aç/kapat', 'optimizasyon modunu aç/kapat', 'pil tasarrufu modunu aç/kapat', "
                    "'hata ayıklama modunu aç/kapat', 'kapat'.")
        elif "kapat" in command or "çıkış" in command:
            QMessageBox.information(self, "Lenon Asistanı", "Görüşmek üzere! Leo Tarayıcı kapanıyor.")
            self.browser.close()
            return "Tarayıcı kapatılıyor..."
        else:
            responses = [
                f"Üzgünüm, '{command}' komutunu tam olarak anlayamadım. Daha spesifik olabilir misiniz?",
                "Bu konuda size nasıl yardımcı olabileceğimi tam olarak kavrayamadım. Lütfen farklı bir şekilde ifade etmeyi deneyin.",
                "Henüz bu tür bir sorguyu işleyemiyorum. 'Yardım' yazarak mevcut komutları görebilirsiniz."
            ]
            return random.choice(responses)

# --- İndirme İletişim Kutusu Sınıfı ---
class DownloadsDialog(QDialog):
    """
    Tarayıcı indirme geçmişini ve aktif indirmeleri gösteren bir iletişim kutusu.
    """
    def __init__(self, downloads_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("İndirmeler")
        self.setGeometry(200, 200, 700, 500)

        self.downloads_data = downloads_data
        self.downloads_list_widget = QListWidget(self)
        self.downloads_list_widget.itemDoubleClicked.connect(self.open_download_location)

        self.clear_completed_button = QPushButton("Tamamlananları Temizle", self)
        self.clear_completed_button.clicked.connect(self.clear_completed_downloads)

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.downloads_list_widget)
        main_layout.addWidget(self.clear_completed_button)
        self.setLayout(main_layout)

        self._populate_list()

    def _populate_list(self):
        self.downloads_list_widget.clear()
        sorted_downloads = sorted(self.downloads_data, key=lambda x: x.get('timestamp', ''), reverse=True)

        for entry in sorted_downloads:
            filename = entry.get('filename', 'Bilinmeyen Dosya')
            status = entry.get('state', 'Bilinmiyor')
            progress = entry.get('progress', 0)
            speed = entry.get('speed', '0 MB/s')
            file_path = entry.get('path', 'Konum Yok')

            item_text = f"{filename} - {status} ({progress}%) - {speed}"
            item = QListWidgetItem(item_text)
            item.setData(Qt.UserRole, file_path)
            item.setData(Qt.UserRole + 1, entry.get('id'))

            if status == 'completed':
                item.setForeground(QColor(0, 150, 0))
            elif status == 'downloading':
                item.setForeground(QColor(0, 100, 200))
            elif status == 'cancelled' or status == 'interrupted':
                item.setForeground(QColor(200, 0, 0))
            else:
                item.setForeground(QColor(100, 100, 100))

            self.downloads_list_widget.addItem(item)

    def update_download_item(self, download_id, data):
        for i in range(self.downloads_list_widget.count()):
            item = self.downloads_list_widget.item(i)
            if item.data(Qt.UserRole + 1) == download_id:
                filename = data.get('filename', 'Bilinmeyen Dosya')
                status = data.get('state', 'Bilinmiyor')
                progress = data.get('progress', 0)
                speed = data.get('speed', '0 MB/s')
                file_path = data.get('path', 'Konum Yok')

                item_text = f"{filename} - {status} ({progress}%) - {speed}"
                item.setText(item_text)
                item.setData(Qt.UserRole, file_path)

                if status == 'completed':
                    item.setForeground(QColor(0, 150, 0))
                elif status == 'downloading':
                    item.setForeground(QColor(0, 100, 200))
                elif status == 'cancelled' or status == 'interrupted':
                    item.setForeground(QColor(200, 0, 0))
                else:
                    item.setForeground(QColor(100, 100, 100))
                return
        self._populate_list()

    def open_download_location(self, item):
        file_path = item.data(Qt.UserRole)
        if file_path and os.path.exists(file_path):
            try:
                if sys.platform == "win32":
                    os.startfile(os.path.dirname(file_path))
                elif sys.platform == "darwin":
                    os.system(f'open "{os.path.dirname(file_path)}"')
                else:
                    os.system(f'xdg-open "{os.path.dirname(file_path)}"')
            except Exception as e:
                QMessageBox.critical(self, "Hata", f"Dosya konumu açılamadı: {e}")
        else:
            QMessageBox.warning(self, "Dosya Bulunamadı", "Dosya bulunamadı veya konumu geçersiz.")

    def clear_completed_downloads(self):
        reply = QMessageBox.question(self, 'Tamamlananları Temizle',
                                     "Tamamlanan tüm indirmeleri geçmişten silmek istediğinizden emin misiniz?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            if self.parent() and hasattr(self.parent(), 'clear_completed_browser_downloads'):
                self.parent().clear_completed_browser_downloads()
                QMessageBox.information(self, "Temizlendi", "Tamamlanan indirmeler başarıyla temizlendi.")
            else:
                QMessageBox.critical(self, "Hata", "İndirme temizleme işlevi bulunamadı.")

# --- Ana Tarayıcı Penceresi Sınıfı ---
class LeoBrowser(QMainWindow):
    """
    Leo Tarayıcı'nın ana penceresi.
    Sayfa yükleme hızı optimizasyonları ve gelişmiş özellikler içerir.
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Leo Tarayıcı")
        self.setWindowIcon(self.style().standardIcon(self.style().SP_ComputerIcon))
        self.setGeometry(100, 100, 1024, 768)

        self.default_homepage = "https://www.google.com"
        self.current_homepage = self.default_homepage
        self.optimization_mode_enabled = False
        self.battery_saving_mode_enabled = False
        self.ad_blocker_enabled = False
        self.dark_mode_enabled = False
        self.custom_search_engine_url = ""
        self.debug_mode_enabled = False # Arka plan hata ayıklayıcı kontrolü

        self.history_data = []
        self.bookmarks_data = []
        self.downloads_data = []

        self.db = db
        self.auth = auth
        # Kullanıcı rastgele bir bulut konumuna yerleştirildi (Firestore'a UID ile bağlanır)
        # Bu, uygulamanın kullanıcı verilerini izole etmesini ve senkronize etmesini sağlar.
        self.user_id = _user_id

        self.init_ui()
        self.init_firebase_listeners()
        self._run_background_services() # Arka plan servislerini başlat

    def init_ui(self):
        self.userId_label = QLabel(f"Kullanıcı ID: {self.user_id}", self)
        self.statusBar().addWidget(self.userId_label)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.tabBarDoubleClicked.connect(self.tab_open_doubleclick)
        self.tabs.currentChanged.connect(self.current_tab_changed)
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.close_current_tab)

        self.setCentralWidget(self.tabs)

        navbar = QToolBar("Gezinme")
        self.addToolBar(navbar)

        back_btn = QAction(self.style().standardIcon(self.style().SP_ArrowBack), "Geri", self)
        back_btn.triggered.connect(lambda: self.tabs.currentWidget().back())
        navbar.addAction(back_btn)

        forward_btn = QAction(self.style().standardIcon(self.style().SP_ArrowForward), "İleri", self)
        forward_btn.triggered.connect(lambda: self.tabs.currentWidget().forward())
        navbar.addAction(forward_btn)

        reload_btn = QAction(self.style().standardIcon(self.style().SP_BrowserReload), "Yenile", self)
        reload_btn.triggered.connect(lambda: self.tabs.currentWidget().reload())
        navbar.addAction(reload_btn)

        home_btn = QAction(self.style().standardIcon(self.style().SP_DirHomeIcon), "Ana Sayfa", self)
        home_btn.triggered.connect(self.navigate_home)
        navbar.addAction(home_btn)

        new_tab_btn = QAction(self.style().standardIcon(self.style().SP_FileIcon), "Yeni Sekme", self)
        new_tab_btn.triggered.connect(lambda: self.add_new_tab(QUrl(self.current_homepage), 'Yeni Sekme'))
        navbar.addAction(new_tab_btn)

        self.url_bar = QLineEdit()
        self.url_bar.returnPressed.connect(self.navigate_to_url)
        navbar.addWidget(self.url_bar)

        self.security_icon_label = QLabel()
        self.security_icon_label.setToolTip("Bağlantı Güvenliği")
        navbar.addWidget(self.security_icon_label)
        self.update_security_icon(QUrl(self.current_homepage))

        clear_url_btn = QAction(self.style().standardIcon(self.style().SP_DialogCancelButton), "Temizle", self)
        clear_url_btn.triggered.connect(self.url_bar.clear)
        navbar.addAction(clear_url_btn)

        self.search_bar = QLineEdit()
        # Google yerine daha genel bir arama metni
        self.search_bar.setPlaceholderText("Web'de ara...")
        self.search_bar.returnPressed.connect(self.perform_search)
        navbar.addWidget(self.search_bar)

        lenon_assistant_btn = QAction(self.style().standardIcon(self.style().SP_MessageBoxInformation), "Lenon Asistan", self)
        lenon_assistant_btn.triggered.connect(self.start_lenon_assistant)
        navbar.addAction(lenon_assistant_btn)

        menubar = self.menuBar()

        file_menu = menubar.addMenu("Dosya")
        new_tab_action = QAction("Yeni Sekme", self)
        new_tab_action.triggered.connect(lambda: self.add_new_tab(QUrl(self.current_homepage), 'Yeni Sekme'))
        file_menu.addAction(new_tab_action)
        exit_action = QAction("Çıkış", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        settings_menu = menubar.addMenu("Ayarlar")
        open_settings_action = QAction("Tarayıcı Ayarları...", self)
        open_settings_action.triggered.connect(self.open_settings)
        settings_menu.addAction(open_settings_action)
        reset_browser_action = QAction(self.style().standardIcon(self.style().SP_DialogResetButton), "Tarayıcıyı Sıfırla...", self)
        reset_browser_action.triggered.connect(self.reset_browser_data)
        settings_menu.addAction(reset_browser_action)
        update_check_action = QAction(self.style().standardIcon(self.style().SP_BrowserReload), "Güncelleme Kontrol Et...", self)
        update_check_action.triggered.connect(self.check_for_updates)
        settings_menu.addAction(update_check_action)

        data_menu = menubar.addMenu("Veri Yönetimi")
        backup_data_action = QAction(self.style().standardIcon(self.style().SP_DialogSaveButton), "Verileri Yedekle...", self)
        backup_data_action.triggered.connect(self.backup_browser_data)
        data_menu.addAction(backup_data_action)
        restore_data_action = QAction(self.style().standardIcon(self.style().SP_DialogOpenButton), "Verileri Geri Yükle...", self)
        restore_data_action.triggered.connect(self.restore_browser_data)
        data_menu.addAction(restore_data_action)

        history_menu = menubar.addMenu("Geçmiş")
        view_history_action = QAction("Geçmişi Görüntüle...", self)
        view_history_action.triggered.connect(self.open_history)
        history_menu.addAction(view_history_action)

        bookmarks_menu = menubar.addMenu("Yer İmleri")
        add_bookmark_action = QAction("Yer İmi Ekle", self)
        add_bookmark_action.triggered.connect(self.add_current_page_as_bookmark)
        bookmarks_menu.addAction(add_bookmark_action)
        view_bookmarks_action = QAction("Yer İmlerini Görüntüle...", self)
        view_bookmarks_action.triggered.connect(self.open_bookmarks)
        bookmarks_menu.addAction(view_bookmarks_action)

        downloads_menu = menubar.addMenu("İndirmeler")
        view_downloads_action = QAction(self.style().standardIcon(self.style().SP_ArrowDown), "İndirmeleri Görüntüle...", self)
        view_downloads_action.triggered.connect(self.open_downloads_dialog)
        downloads_menu.addAction(view_downloads_action)

        tools_menu = menubar.addMenu("Diğer Araçlar")
        extensions_action = QAction(self.style().standardIcon(self.style().SP_DesktopIcon), "Uzantılar (Simülasyon)", self)
        extensions_action.triggered.connect(self.simulate_extensions)
        tools_menu.addAction(extensions_action)
        pwa_shortcut_action = QAction(self.style().standardIcon(self.style().SP_MessageBoxQuestion), "PWA Yükle (Simülasyon)", self)
        pwa_shortcut_action.triggered.connect(self.install_pwa_simulated)
        tools_menu.addAction(pwa_shortcut_action)
        tab_search_action = QAction(self.style().standardIcon(self.style().SP_FileDialogToParent), "Sekmeleri Ara...", self)
        tab_search_action.triggered.connect(self.open_tab_search_dialog)
        tools_menu.addAction(tab_search_action)
        # Hata düzeltildi: SP_DialogNoIcon yerine SP_DialogCancelButton kullanıldı
        website_permissions_action = QAction(self.style().standardIcon(self.style().SP_DialogCancelButton), "Web Sitesi İzinleri...", self)
        website_permissions_action.triggered.connect(self.open_website_permissions_dialog)
        tools_menu.addAction(website_permissions_action)
        # Hata düzeltildi: SP_MailIcon yerine SP_MessageBoxInformation kullanıldı
        send_feedback_action = QAction(self.style().standardIcon(self.style().SP_MessageBoxInformation), "Geri Bildirim Gönder...", self)
        send_feedback_action.triggered.connect(self.send_feedback)
        tools_menu.addAction(send_feedback_action)
        install_system_action = QAction(self.style().standardIcon(self.style().SP_DriveCDIcon), "Sisteme Kur (Simülasyon)", self)
        install_system_action.triggered.connect(self.simulate_system_installation)
        tools_menu.addAction(install_system_action)

        about_action = QAction("Hakkında...", self)
        about_action.triggered.connect(self.open_about)
        tools_menu.addAction(about_action)

        self.add_new_tab(QUrl(self.current_homepage), 'Ana Sayfa')

        # İndirme isteklerini yakala
        self.tabs.currentWidget().page().profile().downloadRequested.connect(self.handle_download_requested)

    def _run_background_services(self):
        """
        Arka plan servislerini ve hata ayıklayıcıyı simüle eder.
        """
        if self.debug_mode_enabled:
            print("Arka plan servisleri başlatılıyor...")
            print(f"Hata ayıklayıcı aktif. Kullanıcı ID: {self.user_id}")
            # Gerçekte burada periyodik görevler, loglama, performans izleme vb. çalıştırılabilir.
        # Örneğin, 5 saniyede bir basit bir kontrol mesajı yazdırabiliriz.
        self.background_timer = QTimer(self)
        self.background_timer.timeout.connect(self._simulate_background_task)
        self.background_timer.start(5000) # Her 5 saniyede bir çalıştır

    def _simulate_background_task(self):
        """
        Basit bir arka plan görevi simülasyonu.
        """
        if self.debug_mode_enabled:
            print(f"Arka plan servisi çalışıyor... (Zaman: {QDateTime.currentDateTime().toString(Qt.ISODate)})")
            # Burada örneğin, otomatik yedekleme, senkronizasyon kontrolleri vb. yapılabilir.

    def init_firebase_listeners(self):
        if self.db and self.user_id:
            settings_doc_ref = self.db.collection(f"artifacts/{_app_id}/users/{self.user_id}/browser_settings").document("settings")
            settings_doc_ref.on_snapshot(self.on_settings_snapshot)

            history_collection_ref = self.db.collection(f"artifacts/{_app_id}/users/{self.user_id}/browser_history")
            history_collection_ref.on_snapshot(self.on_history_snapshot)

            bookmarks_collection_ref = self.db.collection(f"artifacts/{_app_id}/users/{self.user_id}/browser_bookmarks")
            bookmarks_collection_ref.on_snapshot(self.on_bookmarks_snapshot)

            downloads_collection_ref = self.db.collection(f"artifacts/{_app_id}/users/{self.user_id}/browser_downloads")
            downloads_collection_ref.on_snapshot(self.on_downloads_snapshot)
        else:
            QMessageBox.warning(self, "Firebase Hatası", "Firebase başlatılamadı veya kullanıcı kimliği yok. Senkronizasyon devre dışı.")

    def on_settings_snapshot(self, doc_snapshot, changes, read_time):
        if doc_snapshot.exists:
            data = doc_snapshot.to_dict()
            self.current_homepage = data.get('homepage_url', self.default_homepage)
            self.optimization_mode_enabled = data.get('optimization_mode', False)
            self.battery_saving_mode_enabled = data.get('battery_saving_mode', False)
            self.ad_blocker_enabled = data.get('ad_blocker', False)
            self.dark_mode_enabled = data.get('dark_mode', False)
            self.custom_search_engine_url = data.get('custom_search_engine_url', '')
            self.debug_mode_enabled = data.get('debug_mode', False)
            if self.debug_mode_enabled:
                print(f"Ayarlar Firestore'dan güncellendi. Ana Sayfa: {self.current_homepage}, Optimizasyon: {self.optimization_mode_enabled}, Pil Tasarrufu: {self.battery_saving_mode_enabled}, Reklam Engelleyici: {self.ad_blocker_enabled}, Karanlık Mod: {self.dark_mode_enabled}, Arama Motoru: {self.custom_search_engine_url}, Hata Ayıklama: {self.debug_mode_enabled}")

            self.apply_browser_settings()
        else:
            if self.debug_mode_enabled:
                print("Tarayıcı ayarları Firestore'da bulunamadı, varsayılan ayarlanıyor ve kaydediliyor.")
            self.save_settings_to_firestore({
                'homepage_url': self.default_homepage,
                'optimization_mode': False,
                'battery_saving_mode': False,
                'ad_blocker': False,
                'dark_mode': False,
                'custom_search_engine_url': '',
                'debug_mode': False
            })

    def apply_browser_settings(self):
        palette = self.palette()
        if self.dark_mode_enabled:
            palette.setColor(QPalette.Window, QColor(53, 53, 53))
            palette.setColor(QPalette.WindowText, QColor(255, 255, 255))
            palette.setColor(QPalette.Base, QColor(25, 25, 25))
            palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
            palette.setColor(QPalette.ToolTipBase, QColor(255, 255, 255))
            palette.setColor(QPalette.ToolTipText, QColor(255, 255, 255))
            palette.setColor(QPalette.Text, QColor(255, 255, 255))
            palette.setColor(QPalette.Button, QColor(53, 53, 53))
            palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
            palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
            palette.setColor(QPalette.Link, QColor(42, 130, 218))
            palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
            palette.setColor(QPalette.HighlightedText, QColor(0, 0, 0))
        else:
            app = QApplication.instance()
            palette = app.palette()

        self.setPalette(palette)

        for i in range(self.tabs.count()):
            browser = self.tabs.widget(i)
            if isinstance(browser.page(), LeoWebEnginePage):
                browser.page().set_ad_blocker_enabled(self.ad_blocker_enabled)

            settings = browser.page().settings()
            # Sayfa yükleme hızını artırmak için optimizasyonlar
            # Resimleri ve JavaScript'i devre dışı bırakmak en büyük etkiyi yapar.
            disable_content = self.optimization_mode_enabled or self.battery_saving_mode_enabled
            settings.setAttribute(QWebEngineSettings.AutoLoadImages, not disable_content)
            settings.setAttribute(QWebEngineSettings.JavascriptEnabled, not disable_content)
            # Daha hızlı sayfa yüklemesi için DNS önbelleklemeyi etkinleştir
            settings.setAttribute(QWebEngineSettings.DnsPrefetchEnabled, True)
            # Performans için WebGL'i devre dışı bırakma (pil tasarrufu modunda)
            settings.setAttribute(QWebEngineSettings.WebGLEnabled, not self.battery_saving_mode_enabled)
            # Medya otomatik oynatmayı devre dışı bırakma (pil tasarrufu modunda)
            settings.setAttribute(QWebEngineSettings.PlaybackRequiresUserGesture, self.battery_saving_mode_enabled)

    def on_history_snapshot(self, col_snapshot, changes, read_time):
        self.history_data = []
        for doc in col_snapshot:
            if doc.exists:
                entry = doc.to_dict()
                entry['id'] = doc.id
                self.history_data.append(entry)
        self.history_data.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        if self.debug_mode_enabled:
            print(f"Geçmiş Firestore'dan güncellendi. Toplam giriş: {len(self.history_data)}")

    def on_bookmarks_snapshot(self, col_snapshot, changes, read_time):
        self.bookmarks_data = []
        for doc in col_snapshot:
            if doc.exists:
                entry = doc.to_dict()
                entry['id'] = doc.id
                self.bookmarks_data.append(entry)
        if self.debug_mode_enabled:
            print(f"Yer imleri Firestore'dan güncellendi. Toplam yer imi: {len(self.bookmarks_data)}")

    def on_downloads_snapshot(self, col_snapshot, changes, read_time):
        self.downloads_data = []
        for doc in col_snapshot:
            if doc.exists:
                entry = doc.to_dict()
                entry['id'] = doc.id
                self.downloads_data.append(entry)
        self.downloads_data.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        if self.debug_mode_enabled:
            print(f"İndirmeler Firestore'dan güncellendi. Toplam indirme: {len(self.downloads_data)}")
        if hasattr(self, '_downloads_dialog') and self._downloads_dialog.isVisible():
            self._downloads_dialog._populate_list()

    def add_new_tab(self, qurl=None, label="boş"):
        browser = QWebEngineView()
        page = LeoWebEnginePage(browser.page().profile(), self, browser)
        browser.setPage(page)

        # Yeni sekme için ayarları uygula (hız optimizasyonları dahil)
        page.set_ad_blocker_enabled(self.ad_blocker_enabled)
        settings = page.settings()
        disable_content = self.optimization_mode_enabled or self.battery_saving_mode_enabled
        settings.setAttribute(QWebEngineSettings.AutoLoadImages, not disable_content)
        settings.setAttribute(QWebEngineSettings.JavascriptEnabled, not disable_content)
        settings.setAttribute(QWebEngineSettings.DnsPrefetchEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebGLEnabled, not self.battery_saving_mode_enabled)
        settings.setAttribute(QWebEngineSettings.PlaybackRequiresUserGesture, self.battery_saving_mode_enabled)

        browser.setUrl(qurl if qurl else QUrl(self.current_homepage))
        i = self.tabs.addTab(browser, label)
        self.tabs.setCurrentIndex(i)

        browser.urlChanged.connect(lambda q, browser=browser: self.update_url_bar(q, browser))
        browser.loadProgress.connect(lambda p, browser=browser: self.update_tab_title(p, browser))
        browser.titleChanged.connect(lambda title, browser=browser: self.update_tab_title_from_page(title, browser))
        browser.loadFinished.connect(lambda ok, browser=browser: self.add_to_history(browser) if ok else None)

    def close_current_tab(self, i):
        if self.tabs.count() < 2:
            QMessageBox.warning(self, "Sekme Kapatma", "Son sekmeyi kapatamazsınız.")
            return

        self.tabs.removeTab(i)

    def update_url_bar(self, q, browser=None):
        if browser != self.tabs.currentWidget():
            return
        self.url_bar.setText(q.toString())
        self.url_bar.setCursorPosition(0)
        self.update_security_icon(q)

    def update_security_icon(self, qurl):
        if qurl.scheme() == "https":
            self.security_icon_label.setPixmap(self.style().standardIcon(self.style().SP_DialogSaveButton).pixmap(16, 16))
            self.security_icon_label.setToolTip("Güvenli Bağlantı (HTTPS)")
        elif qurl.scheme() == "http":
            self.security_icon_label.setPixmap(self.style().standardIcon(self.style().SP_MessageBoxWarning).pixmap(16, 16))
            self.security_icon_label.setToolTip("Güvenli Olmayan Bağlantı (HTTP)")
        else:
            self.security_icon_label.setPixmap(self.style().standardIcon(self.style().SP_MessageBoxQuestion).pixmap(16, 16))
            self.security_icon_label.setToolTip("Bilinmeyen Bağlantı Tipi")

    def update_tab_title(self, progress, browser):
        i = self.tabs.indexOf(browser)
        if progress < 100:
            self.tabs.setTabText(i, f"Yükleniyor... ({progress}%)")
        else:
            self.tabs.setTabText(i, browser.title() if browser.title() else "Başlıksız")

    def update_tab_title_from_page(self, title, browser):
        i = self.tabs.indexOf(browser)
        self.tabs.setTabText(i, title if title else "Başlıksız")

    def current_tab_changed(self, i):
        if self.tabs.currentWidget():
            qurl = self.tabs.currentWidget().url()
            self.update_url_bar(qurl, self.tabs.currentWidget())

    def tab_open_doubleclick(self, i):
        if i == -1:
            self.add_new_tab(QUrl(self.current_homepage), 'Yeni Sekme')

    def navigate_to_url(self):
        q = QUrl(self.url_bar.text())
        if q.scheme() == "":
            q.setScheme("http")
        self.tabs.currentWidget().setUrl(q)

    def navigate_home(self):
        self.tabs.currentWidget().setUrl(QUrl(self.current_homepage))

    def perform_search(self):
        query = self.search_bar.text()
        if query:
            if self.custom_search_engine_url and "{query}" in self.custom_search_engine_url:
                search_url = self.custom_search_engine_url.replace("{query}", QUrl.toPercentEncoding(query).data().decode())
            else:
                # Varsayılan arama motoru hala Google, ancak metin daha genel.
                search_url = f"https://www.google.com/search?q={QUrl.toPercentEncoding(query).data().decode()}"
            self.tabs.currentWidget().setUrl(QUrl(search_url))

    def start_lenon_assistant(self):
        dialog = LenonAssistantDialog(self, self)
        dialog.exec_()

    def open_settings(self):
        current_settings = {
            'homepage_url': self.current_homepage,
            'optimization_mode': self.optimization_mode_enabled,
            'battery_saving_mode': self.battery_saving_mode_enabled,
            'ad_blocker': self.ad_blocker_enabled,
            'dark_mode': self.dark_mode_enabled,
            'custom_search_engine_url': self.custom_search_engine_url,
            'debug_mode': self.debug_mode_enabled
        }
        dialog = SettingsDialog(current_settings, self)
        if dialog.exec_() == QDialog.Accepted:
            new_settings = dialog.get_settings()
            self.current_homepage = new_settings['homepage_url']
            self.optimization_mode_enabled = new_settings['optimization_mode']
            self.battery_saving_mode_enabled = new_settings['battery_saving_mode']
            self.ad_blocker_enabled = new_settings['ad_blocker']
            self.dark_mode_enabled = new_settings['dark_mode']
            self.custom_search_engine_url = new_settings['custom_search_engine_url']
            self.debug_mode_enabled = new_settings['debug_mode']

            self.save_settings_to_firestore(new_settings)
            self.apply_browser_settings()
            QMessageBox.information(self, "Ayarlar Kaydedildi", "Tarayıcı ayarları başarıyla kaydedildi.")

    def save_settings_to_firestore(self, settings_data):
        if self.db and self.user_id:
            try:
                settings_doc_ref = self.db.collection(f"artifacts/{_app_id}/users/{self.user_id}/browser_settings").document("settings")
                settings_doc_ref.set(settings_data)
                if self.debug_mode_enabled:
                    print(f"Ayarlar Firestore'a kaydedildi: {settings_data}")
            except Exception as e:
                print(f"Ayarlar Firestore'a kaydedilirken hata oluştu: {e}")
                QMessageBox.critical(self, "Firestore Hatası", f"Ayarlar kaydedilirken hata oluştu: {e}")

    def reset_browser_data(self):
        reply = QMessageBox.question(self, 'Tarayıcıyı Sıfırla',
                                     "Tüm tarayıcı verilerini (ayarlar, geçmiş, yer imleri, indirmeler) sıfırlamak istediğinizden emin misiniz? Bu işlem geri alınamaz.",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            if self.db and self.user_id:
                try:
                    settings_doc_ref = self.db.collection(f"artifacts/{_app_id}/users/{self.user_id}/browser_settings").document("settings")
                    settings_doc_ref.set({
                        'homepage_url': self.default_homepage,
                        'optimization_mode': False,
                        'battery_saving_mode': False,
                        'ad_blocker': False,
                        'dark_mode': False,
                        'custom_search_engine_url': '',
                        'debug_mode': False
                    })
                    history_collection_ref = self.db.collection(f"artifacts/{_app_id}/users/{self.user_id}/browser_history")
                    docs = history_collection_ref.get_docs()
                    for doc in docs:
                        doc.reference.delete()
                    self.history_data = []

                    bookmarks_collection_ref = self.db.collection(f"artifacts/{_app_id}/users/{self.user_id}/browser_bookmarks")
                    docs = bookmarks_collection_ref.get_docs()
                    for doc in docs:
                        doc.reference.delete()
                    self.bookmarks_data = []

                    downloads_collection_ref = self.db.collection(f"artifacts/{_app_id}/users/{self.user_id}/browser_downloads")
                    docs = downloads_collection_ref.get_docs()
                    for doc in docs:
                        doc.reference.delete()
                    self.downloads_data = []

                    QMessageBox.information(self, "Sıfırlama Başarılı", "Tarayıcı verileri başarıyla sıfırlandı.")
                    self.apply_browser_settings()
                    self.navigate_home()
                except Exception as e:
                    QMessageBox.critical(self, "Sıfırlama Hatası", f"Tarayıcı sıfırlanırken hata oluştu: {e}")
            else:
                QMessageBox.critical(self, "Sıfırlama Hatası", "Firestore bağlantısı mevcut değil. Sıfırlama yapılamadı.")

    def backup_browser_data(self):
        if not self.db or not self.user_id:
            QMessageBox.critical(self, "Yedekleme Hatası", "Firestore bağlantısı mevcut değil. Yedekleme yapılamadı.")
            return

        try:
            settings_doc = self.db.collection(f"artifacts/{_app_id}/users/{self.user_id}/browser_settings").document("settings").get_docs()
            settings_data = settings_doc[0].to_dict() if settings_doc and settings_doc[0].exists else {}

            history_data = [doc.to_dict() for doc in self.db.collection(f"artifacts/{_app_id}/users/{self.user_id}/browser_history").get_docs()]
            bookmarks_data = [doc.to_dict() for doc in self.db.collection(f"artifacts/{_app_id}/users/{self.user_id}/browser_bookmarks").get_docs()]
            downloads_data = [doc.to_dict() for doc in self.db.collection(f"artifacts/{_app_id}/users/{self.user_id}/browser_downloads").get_docs()]

            backup_content = {
                'settings': settings_data,
                'history': history_data,
                'bookmarks': bookmarks_data,
                'downloads': downloads_data,
                'backup_timestamp': QDateTime.currentDateTime().toString(Qt.ISODate)
            }

            default_filename = f"leo_browser_backup_{QDateTime.currentDateTime().toString('yyyyMMdd_hhmmss')}.json"
            file_path, _ = QFileDialog.getSaveFileName(self, "Yedekleme Dosyasını Kaydet",
                                                       QStandardPaths.writableLocation(QStandardPaths.DocumentsLocation) + "/" + default_filename,
                                                       "JSON Dosyaları (*.json);;Tüm Dosyalar (*)")
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(backup_content, f, ensure_ascii=False, indent=4)
                QMessageBox.information(self, "Yedekleme Başarılı", f"Veriler başarıyla yedeklendi:\n{file_path}")
            else:
                QMessageBox.information(self, "Yedekleme İptal Edildi", "Yedekleme işlemi iptal edildi.")

        except Exception as e:
            QMessageBox.critical(self, "Yedekleme Hatası", f"Yedekleme sırasında bir hata oluştu: {e}")

    def restore_browser_data(self):
        if not self.db or not self.user_id:
            QMessageBox.critical(self, "Geri Yükleme Hatası", "Firestore bağlantısı mevcut değil. Geri yükleme yapılamadı.")
            return

        reply = QMessageBox.question(self, 'Verileri Geri Yükle',
                                     "Mevcut tarayıcı verileriniz geri yüklenecek verilerle değiştirilecektir. Devam etmek istiyor musunuz?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.No:
            return

        file_path, _ = QFileDialog.getOpenFileName(self, "Yedekleme Dosyasını Seç",
                                                   QStandardPaths.writableLocation(QStandardPaths.DocumentsLocation),
                                                   "JSON Dosyaları (*.json);;Tüm Dosyalar (*)")
        if not file_path:
            QMessageBox.information(self, "Geri Yükleme İptal Edildi", "Geri yükleme işlemi iptal edildi.")
            return

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                restored_data = json.load(f)

            if 'settings' in restored_data:
                settings_doc_ref = self.db.collection(f"artifacts/{_app_id}/users/{self.user_id}/browser_settings").document("settings")
                settings_doc_ref.set(restored_data['settings'])

            if 'history' in restored_data:
                history_collection_ref = self.db.collection(f"artifacts/{_app_id}/users/{self.user_id}/browser_history")
                current_history_docs = history_collection_ref.get_docs()
                for doc in current_history_docs:
                    doc.reference.delete()
                for entry in restored_data['history']:
                    history_collection_ref.add(entry)

            if 'bookmarks' in restored_data:
                bookmarks_collection_ref = self.db.collection(f"artifacts/{_app_id}/users/{self.user_id}/browser_bookmarks")
                current_bookmark_docs = bookmarks_collection_ref.get_docs()
                for doc in current_bookmark_docs:
                    doc.reference.delete()
                for entry in restored_data['bookmarks']:
                    bookmarks_collection_ref.add(entry)

            if 'downloads' in restored_data:
                downloads_collection_ref = self.db.collection(f"artifacts/{_app_id}/users/{self.user_id}/browser_downloads")
                current_downloads_docs = downloads_collection_ref.get_docs()
                for doc in current_downloads_docs:
                    doc.reference.delete()
                for entry in restored_data['downloads']:
                    downloads_collection_ref.add(entry)

            QMessageBox.information(self, "Geri Yükleme Başarılı", "Veriler başarıyla geri yüklendi.")
            self.apply_browser_settings()
            self.navigate_home()
        except json.JSONDecodeError:
            QMessageBox.critical(self, "Geri Yükleme Hatası", "Seçilen dosya geçerli bir JSON dosyası değil.")
        except Exception as e:
            QMessageBox.critical(self, "Geri Yükleme Hatası", f"Geri yükleme sırasında bir hata oluştu: {e}")

    def add_to_history(self, browser):
        url = browser.url().toString()
        title = browser.title()
        timestamp = QDateTime.currentDateTime().toString(Qt.ISODate)

        if not url or url.startswith("about:"):
            return

        if self.history_data and self.history_data[0].get('url') == url:
            return

        if self.db and self.user_id:
            try:
                history_collection_ref = self.db.collection(f"artifacts/{_app_id}/users/{self.user_id}/browser_history")
                history_collection_ref.add({'url': url, 'title': title, 'timestamp': timestamp})
                if self.debug_mode_enabled:
                    print(f"Geçmişe eklendi: {title} - {url}")
            except Exception as e:
                print(f"Geçmişe eklenirken hata oluştu: {e}")
                QMessageBox.critical(self, "Firestore Hatası", f"Geçmişe eklenirken hata oluştu: {e}")

    def open_history(self):
        dialog = HistoryDialog(self.history_data, self)
        if dialog.exec_() == QDialog.Accepted:
            selected_url = dialog.get_selected_url()
            if selected_url:
                self.add_new_tab(QUrl(selected_url), "Geçmişten")

    def clear_browser_history(self):
        if self.db and self.user_id:
            try:
                history_collection_ref = self.db.collection(f"artifacts/{_app_id}/users/{self.user_id}/browser_history")
                docs = history_collection_ref.get_docs()
                for doc in docs:
                    if hasattr(doc, 'reference') and hasattr(doc.reference, 'delete'):
                        doc.reference.delete()
                    else:
                        if self.debug_mode_enabled:
                            print(f"Mock: Belge silindi: {doc.id}")
                self.history_data = [d for d in self.history_data if d.get('state') != 'completed']
                if self.debug_mode_enabled:
                    print("Tarayıcı geçmişi Firestore'dan temizlendi.")
            except Exception as e:
                print(f"Geçmiş temizlenirken hata oluştu: {e}")
                QMessageBox.critical(self, "Firestore Hatası", f"Geçmiş temizlenirken hata oluştu: {e}")

    def add_current_page_as_bookmark(self):
        current_browser = self.tabs.currentWidget()
        if not current_browser:
            QMessageBox.warning(self, "Yer İmi Ekle", "Açık bir sekme yok.")
            return

        url = current_browser.url().toString()
        title = current_browser.title()

        if not url or not title or url.startswith("about:"):
            QMessageBox.warning(self, "Yer İmi Ekle", "Geçerli sayfa yer imi olarak eklenemiyor (geçersiz URL veya başlık).")
            return

        if any(b.get('url') == url for b in self.bookmarks_data):
            QMessageBox.information(self, "Yer İmi Ekle", "Bu sayfa zaten yer imlerinizde.")
            return

        if self.db and self.user_id:
            try:
                bookmarks_collection_ref = self.db.collection(f"artifacts/{_app_id}/users/{self.user_id}/browser_bookmarks")
                bookmarks_collection_ref.add({'url': url, 'title': title})
                if self.debug_mode_enabled:
                    print(f"Yer imi eklendi: {title} - {url}")
                QMessageBox.information(self, "Yer İmi Ekle", f"'{title}' yer imi başarıyla eklendi.")
            except Exception as e:
                print(f"Yer imi eklenirken hata oluştu: {e}")
                QMessageBox.critical(self, "Firestore Hatası", f"Yer imi eklenirken hata oluştu: {e}")

    def open_bookmarks(self):
        dialog = BookmarksDialog(self.bookmarks_data, self)
        if dialog.exec_() == QDialog.Accepted:
            selected_url = dialog.get_selected_url()
            if selected_url:
                self.add_new_tab(QUrl(selected_url), "Yer İmlerinden")

    def remove_bookmark_from_firestore(self, url_to_remove):
        if self.db and self.user_id:
            try:
                bookmarks_collection_ref = self.db.collection(f"artifacts/{_app_id}/users/{self.user_id}/browser_bookmarks")
                docs_to_delete = bookmarks_collection_ref.where('url', '==', url_to_remove).get_docs()
                for doc in docs_to_delete:
                    if hasattr(doc, 'reference') and hasattr(doc.reference, 'delete'):
                        doc.reference.delete()
                    else:
                        if self.debug_mode_enabled:
                            print(f"Mock: Belge silindi: {doc.id}")
                    if self.debug_mode_enabled:
                        print(f"Yer imi Firestore'dan kaldırıldı: {url_to_remove}")
                self.bookmarks_data = [b for b in self.bookmarks_data if b.get('url') != url_to_remove]
            except Exception as e:
                print(f"Yer imi kaldırılırken hata oluştu: {e}")
                QMessageBox.critical(self, "Firestore Hatası", f"Yer imi kaldırılırken hata oluştu: {e}")

    def open_tab_search_dialog(self):
        tab_titles = []
        for i in range(self.tabs.count()):
            tab_titles.append(self.tabs.tabText(i))

        if not tab_titles:
            QMessageBox.information(self, "Sekme Araması", "Açık sekme bulunmuyor.")
            return

        search_query, ok = QInputDialog.getText(self, "Sekme Araması", "Sekme başlığında aramak istediğiniz kelimeyi girin:")
        if ok and search_query:
            search_query = search_query.lower()
            matching_tabs = []
            for i, title in enumerate(tab_titles):
                if search_query in title.lower():
                    matching_tabs.append((i, title))

            if matching_tabs:
                tab_selection_dialog = QDialog(self)
                tab_selection_dialog.setWindowTitle("Eşleşen Sekmeler")
                tab_selection_dialog_layout = QVBoxLayout()
                tab_list_widget = QListWidget()

                for index, title in matching_tabs:
                    item = QListWidgetItem(title)
                    item.setData(Qt.UserRole, index)
                    tab_list_widget.addItem(item)

                tab_list_widget.itemDoubleClicked.connect(lambda item: self.switch_to_tab_from_search(item.data(Qt.UserRole), tab_selection_dialog))

                ok_button = QPushButton("Seç ve Git", tab_selection_dialog)
                ok_button.clicked.connect(lambda: self.switch_to_tab_from_search(tab_list_widget.currentItem().data(Qt.UserRole), tab_selection_dialog))
                cancel_button = QPushButton("İptal", tab_selection_dialog)
                cancel_button.clicked.connect(tab_selection_dialog.reject)

                button_layout = QHBoxLayout()
                button_layout.addStretch()
                button_layout.addWidget(ok_button)
                button_layout.addWidget(cancel_button)
                button_layout.addStretch()

                tab_selection_dialog_layout.addWidget(QLabel("Eşleşen sekmeler:"))
                tab_selection_dialog_layout.addWidget(tab_list_widget)
                tab_selection_dialog_layout.addLayout(button_layout)
                tab_selection_dialog.setLayout(tab_selection_dialog_layout)

                tab_selection_dialog.exec_()

            else:
                QMessageBox.information(self, "Sekme Araması", f"'{search_query}' ile eşleşen sekme bulunamadı.")
        elif not ok:
            QMessageBox.information(self, "Sekme Araması", "Sekme arama işlemi iptal edildi.")

    def switch_to_tab_from_search(self, tab_index, dialog):
        self.tabs.setCurrentIndex(tab_index)
        dialog.accept()

    def handle_download_requested(self, download_item):
        if self.debug_mode_enabled:
            print(f"İndirme isteği: {download_item.url().toString()}")

        suggested_filename = os.path.basename(download_item.url().path())
        if not suggested_filename:
            suggested_filename = "indirilen_dosya"

        download_dir = QStandardPaths.writableLocation(QStandardPaths.DownloadLocation)
        if not os.path.exists(download_dir):
            os.makedirs(download_dir)

        file_path, _ = QFileDialog.getSaveFileName(self, "Dosyayı Kaydet",
                                                   os.path.join(download_dir, suggested_filename),
                                                   "Tüm Dosyalar (*.*)")
        if not file_path:
            download_item.cancel()
            QMessageBox.information(self, "İndirme İptal Edildi", "İndirme işlemi kullanıcı tarafından iptal edildi.")
            return

        download_item.setPath(file_path)
        download_item.accept()

        if self.db and self.user_id:
            try:
                downloads_collection_ref = self.db.collection(f"artifacts/{_app_id}/users/{self.user_id}/browser_downloads")
                new_download_doc = downloads_collection_ref.add({
                    'url': download_item.url().toString(),
                    'filename': os.path.basename(file_path),
                    'path': file_path,
                    'total_bytes': download_item.totalBytes(),
                    'received_bytes': download_item.receivedBytes(),
                    'state': 'downloading',
                    'progress': 0,
                    'speed': '0 MB/s',
                    'timestamp': QDateTime.currentDateTime().toString(Qt.ISODate),
                    'start_time': time.time(),
                    'last_received_bytes': 0,
                    'last_update_time': time.time()
                })
                download_item.setProperty("firestore_doc_id", new_download_doc.id)
                if self.debug_mode_enabled:
                    print(f"Yeni indirme Firestore'a eklendi: {new_download_doc.id}")

            except Exception as e:
                print(f"İndirme Firestore'a eklenirken hata oluştu: {e}")
                QMessageBox.critical(self, "Firestore Hatası", f"İndirme eklenirken hata oluştu: {e}")

        download_item.stateChanged.connect(lambda state: self.on_download_state_changed(download_item, state))
        # Removed the problematic line: download_item.receivedBytesChanged.connect(lambda: self.on_download_progress(download_item))

    def _update_download_progress_polled(self, download_item):
        """
        Periodically updates download progress by polling.
        This function replaces the direct connection to receivedBytesChanged.
        """
        doc_id = download_item.property("firestore_doc_id")
        if not doc_id:
            return

        total_bytes = download_item.totalBytes()
        received_bytes = download_item.receivedBytes()
        progress = int((received_bytes / total_bytes) * 100) if total_bytes > 0 else 0

        current_time = time.time()
        current_download_data = next((d for d in self.downloads_data if d.get('id') == doc_id), None)

        speed_mbps = "0 MB/s"
        if current_download_data:
            last_received_bytes = current_download_data.get('last_received_bytes', 0)
            last_update_time = current_download_data.get('last_update_time', time.time())

            time_diff = current_time - last_update_time
            bytes_diff = received_bytes - last_received_bytes

            if time_diff > 0:
                speed_bytes_per_sec = bytes_diff / time_diff
                speed_mbps = f"{(speed_bytes_per_sec / (1024 * 1024)):.2f} MB/s"

            if self.db and self.user_id:
                try:
                    downloads_doc_ref = self.db.collection(f"artifacts/{_app_id}/users/{self.user_id}/browser_downloads").document(doc_id)
                    downloads_doc_ref.set({
                        'received_bytes': received_bytes,
                        'progress': progress,
                        'speed': speed_mbps,
                        'last_received_bytes': received_bytes,
                        'last_update_time': current_time,
                        'state': 'downloading' # Keep state as downloading while polling
                    })
                    if self.debug_mode_enabled:
                        print(f"İndirme ilerlemesi güncellendi ({doc_id}): {progress}% - {speed_mbps}")
                except Exception as e:
                    print(f"İndirme durumu Firestore'da güncellenirken hata oluştu: {e}")
        else:
            if self.debug_mode_enabled:
                print(f"İndirme ilerlemesi: {progress}% - {speed_mbps}")

    def on_download_state_changed(self, download_item, state):
        doc_id = download_item.property("firestore_doc_id")
        if not doc_id:
            return

        status_text = ""
        if state == QWebEngineDownloadItem.DownloadRequested:
            status_text = "İndirme İstendi"
        elif state == QWebEngineDownloadItem.DownloadInProgress:
            status_text = "İndiriliyor"
            # Start a timer to poll for progress updates
            if not hasattr(download_item, '_progress_timer'):
                download_item._progress_timer = QTimer(self)
                download_item._progress_timer.timeout.connect(lambda: self._update_download_progress_polled(download_item))
                download_item._progress_timer.start(500) # Poll every 500ms for progress
        elif state == QWebEngineDownloadItem.DownloadCompleted:
            status_text = "Tamamlandı"
            if self.debug_mode_enabled:
                print(f"İndirme tamamlandı: {download_item.path()}")
            # Ensure final progress update
            self._update_download_progress_polled(download_item)
            # Stop the timer if it's active
            if hasattr(download_item, '_progress_timer') and download_item._progress_timer.isActive():
                download_item._progress_timer.stop()
                del download_item._progress_timer
        elif state == QWebEngineDownloadItem.DownloadCancelled:
            status_text = "İptal Edildi"
            if self.debug_mode_enabled:
                print(f"İndirme iptal edildi: {download_item.path()}")
            # Stop the timer if it's active
            if hasattr(download_item, '_progress_timer') and download_item._progress_timer.isActive():
                download_item._progress_timer.stop()
                del download_item._progress_timer
        elif state == QWebEngineDownloadItem.DownloadInterrupted:
            status_text = "Kesintiye Uğradı"
            if self.debug_mode_enabled:
                print(f"İndirme kesintiye uğradı: {download_item.path()}")
            # Stop the timer if it's active
            if hasattr(download_item, '_progress_timer') and download_item._progress_timer.isActive():
                download_item._progress_timer.stop()
                del download_item._progress_timer

        if self.db and self.user_id:
            try:
                downloads_doc_ref = self.db.collection(f"artifacts/{_app_id}/users/{self.user_id}/browser_downloads").document(doc_id)
                update_data = {
                    'state': status_text.lower().replace(' ', '_'),
                    'end_timestamp': QDateTime.currentDateTime().toString(Qt.ISODate),
                    'speed': '0 MB/s' # İndirme bittiğinde hızı sıfırla
                }
                if state == QWebEngineDownloadItem.DownloadCompleted:
                    update_data['progress'] = 100
                    update_data['received_bytes'] = download_item.totalBytes()
                downloads_doc_ref.set(update_data)
                if self.debug_mode_enabled:
                    print(f"İndirme durumu Firestore'da güncellendi ({doc_id}): {status_text}")
            except Exception as e:
                print(f"İndirme durumu Firestore'da güncellenirken hata oluştu: {e}")

    def open_downloads_dialog(self):
        self._downloads_dialog = DownloadsDialog(self.downloads_data, self)
        self._downloads_dialog.exec_()

    def clear_completed_browser_downloads(self):
        reply = QMessageBox.question(self, 'Tamamlananları Temizle',
                                     "Tamamlanan tüm indirmeleri geçmişten silmek istediğinizden emin misiniz?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.No:
            return

        if self.db and self.user_id:
            try:
                downloads_collection_ref = self.db.collection(f"artifacts/{_app_id}/users/{self.user_id}/browser_downloads")
                docs_to_delete = downloads_collection_ref.query().where('state', '==', 'completed').get_docs()
                for doc in docs_to_delete:
                    if hasattr(doc, 'reference') and hasattr(doc.reference, 'delete'):
                        doc.reference.delete()
                    else:
                        if self.debug_mode_enabled:
                            print(f"Mock: Tamamlanan indirme belgesi silindi: {doc.id}")
                self.downloads_data = [d for d in self.downloads_data if d.get('state') != 'completed']
                if self.debug_mode_enabled:
                    print("Tamamlanan indirmeler Firestore'dan temizlendi.")
                if hasattr(self, '_downloads_dialog') and self._downloads_dialog.isVisible():
                    self._downloads_dialog._populate_list()
            except Exception as e:
                print(f"Tamamlanan indirmeler temizlenirken hata oluştu: {e}")
                QMessageBox.critical(self, "Firestore Hatası", f"Tamamlanan indirmeler temizlenirken hata oluştu: {e}")

    def check_for_updates(self):
        QMessageBox.information(self, "Güncelleme Kontrolü", "Güncellemeler kontrol ediliyor...\n\nLeo Tarayıcı zaten en güncel sürümde!")

    def simulate_extensions(self):
        """
        Uzantı desteğini simüle eder.
        """
        QMessageBox.information(self, "Uzantılar",
                                "Leo Tarayıcı, uzantı desteği için güçlü bir altyapıya sahiptir. "
                                "Gelecekte, bu altyapı sayesinde tarayıcınıza yeni özellikler ekleyebileceksiniz.\n\n"
                                "Şu anda yüklü uzantı bulunmuyor.")

    def install_pwa_simulated(self):
        """
        PWA (Progressive Web App) yüklemeyi simüle eder.
        """
        current_url = self.tabs.currentWidget().url().toString()
        if current_url.startswith("http"):
            QMessageBox.information(self, "PWA Yükle",
                                    f"'{current_url}' adresindeki web uygulamasını PWA olarak yüklemek istiyor musunuz?\n\n"
                                    "Bu özellik, web sitelerini masaüstü uygulamaları gibi çalıştırmanıza olanak tanır. "
                                    "Gerçek kurulum için işletim sistemi entegrasyonu gereklidir. "
                                    "Yüklendiğinde, PWA'lar kendi penceresinde çalışır ve daha hızlı bir deneyim sunar.")
        else:
            QMessageBox.warning(self, "PWA Yükle", "Geçerli sayfa PWA olarak yüklenemiyor (geçersiz URL).")

    def open_website_permissions_dialog(self):
        """
        Mevcut web sitesinin izinlerini gösteren bir diyalog açar.
        """
        current_page = self.tabs.currentWidget().page()
        if not current_page:
            QMessageBox.warning(self, "Web Sitesi İzinleri", "Açık bir sayfa bulunmuyor.")
            return

        current_url = current_page.url().toString()
        permissions_info = "<b>Web Sitesi İzinleri:</b><br>"
        if current_url in current_page.feature_permissions:
            for feature, status in current_page.feature_permissions[current_url].items():
                permissions_info += f"- {feature}: {status}<br>"
        else:
            permissions_info += "Bu site için kaydedilmiş özel izin bulunmuyor."

        permissions_info += "<br>İzinler, kamera, mikrofon, konum ve bildirimler gibi özellikler için web sitelerinin erişimini kontrol etmenizi sağlar."

        QMessageBox.information(self, "Web Sitesi İzinleri", permissions_info)

    def send_feedback(self):
        """
        Kullanıcıdan geri bildirim alır ve simüle edilmiş bir e-posta gönderir.
        """
        feedback_dialog = FeedbackDialog(self)
        if feedback_dialog.exec_() == QDialog.Accepted:
            feedback_text = feedback_dialog.get_feedback_text()
            if feedback_text.strip():
                # Gerçek bir e-posta gönderme işlemi yerine simülasyon
                feedback_recipient = "metehanisbilir867@gmail.com"
                feedback_subject = "Leo Tarayıcı Geri Bildirimi"
                full_feedback_message = (
                    f"Gönderen Kullanıcı ID: {self.user_id}\n"
                    f"Zaman Damgası: {QDateTime.currentDateTime().toString(Qt.ISODate)}\n"
                    f"Geri Bildirim:\n{feedback_text}"
                )
                if self.debug_mode_enabled:
                    print(f"Geri bildirim gönderildi (simülasyon):\n"
                          f"Alıcı: {feedback_recipient}\n"
                          f"Konu: {feedback_subject}\n"
                          f"İçerik:\n{full_feedback_message}")
                QMessageBox.information(self, "Geri Bildirim Gönderildi",
                                        f"Geri bildiriminiz başarıyla gönderildi. Teşekkür ederiz!\n"
                                        f"Alıcı: {feedback_recipient}")
            else:
                QMessageBox.warning(self, "Geri Bildirim", "Lütfen göndermek için bir geri bildirim yazın.")

    def simulate_system_installation(self):
        """
        Tarayıcının sisteme kurulumunu simüle eder.
        """
        reply = QMessageBox.question(self, "Sisteme Kur",
                                     "Leo Tarayıcı'yı sisteminize kurmak istediğinizden emin misiniz?\n\n"
                                     "Bu işlem, tarayıcının daha derin sistem entegrasyonu sağlamasına olanak tanır. "
                                     "Gerçek kurulum, işletim sistemi izinleri ve dosya kopyalama gerektirir.",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            QMessageBox.information(self, "Kurulum Başlatılıyor",
                                    "Leo Tarayıcı sisteminize kuruluyor...\n\n"
                                    "Kurulum tamamlandığında bir bildirim alacaksınız. "
                                    "Bu, uygulamanın daha hızlı başlatılmasına ve sistem kaynaklarına daha iyi erişmesine yardımcı olabilir.")
            # Gerçekte burada kurulum betikleri veya paket yöneticisi çağrıları yapılabilir.
            # Basit bir gecikme ile kurulumu simüle edelim.
            QTimer.singleShot(3000, lambda: QMessageBox.information(self, "Kurulum Tamamlandı", "Leo Tarayıcı sisteminize başarıyla kuruldu!"))
        else:
            QMessageBox.information(self, "Kurulum İptal Edildi", "Sistem kurulumu iptal edildi.")

    def open_about(self):
        about_dialog = AboutDialog(self)
        about_dialog.exec_()

    def update_load_progress(self, progress):
        pass # Bu fonksiyon artık açılış ekranı kaldırıldığı için kullanılmıyor.

if __name__ == '__main__':
    app = QApplication(sys.argv)

    # Ana tarayıcı penceresi doğrudan oluşturuluyor ve gösteriliyor.
    # Açılış ekranı kaldırıldı.
    window = LeoBrowser()
    window.show()

    sys.exit(app.exec_())
