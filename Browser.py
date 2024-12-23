import sys
import json
from PyQt5.QtWidgets import QApplication, QMainWindow, QToolBar, QAction, QLineEdit, QVBoxLayout, QWidget, QMenu, QMessageBox
from PyQt5.QtCore import QUrl
from PyQt5.QtWebEngineWidgets import QWebEngineView

class Browser(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Gorstaks Browser")
        self.setGeometry(300, 300, 1024, 768)

        # Set up the browser
        self.browser = QWebEngineView()
        self.browser.setUrl(QUrl("https://www.google.com"))

        # Create a toolbar for navigation
        navtb = QToolBar("Navigation")
        self.addToolBar(navtb)

        # Back button
        back_btn = QAction("Back", self)
        back_btn.triggered.connect(self.browser.back)
        navtb.addAction(back_btn)

        # Forward button
        forward_btn = QAction("Forward", self)
        forward_btn.triggered.connect(self.browser.forward)
        navtb.addAction(forward_btn)

        # Reload button
        reload_btn = QAction("Reload", self)
        reload_btn.triggered.connect(self.browser.reload)
        navtb.addAction(reload_btn)

        # Home button
        home_btn = QAction("Home", self)
        home_btn.triggered.connect(self.navigate_home)
        navtb.addAction(home_btn)

        # URL bar
        self.urlbar = QLineEdit()
        self.urlbar.returnPressed.connect(self.navigate_to_url)
        navtb.addWidget(self.urlbar)

        self.browser.urlChanged.connect(self.update_urlbar)

        # Add browser to the layout
        layout = QVBoxLayout()
        layout.addWidget(self.browser)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def navigate_home(self):
        self.browser.setUrl(QUrl("https://www.google.com"))

    def navigate_to_url(self):
        url = self.urlbar.text()
        if not url.startswith("http"):
            url = "http://" + url
        self.browser.setUrl(QUrl(url))

    def update_urlbar(self, q):
        self.urlbar.setText(q.toString())

    def add_bookmark(self):
        url = self.browser.url().toString()
        title = self.browser.title()
        bookmark = {"title": title, "url": url}

        # Save to bookmarks.json
        try:
            with open("bookmarks.json", "r+") as file:
                bookmarks = json.load(file)
                bookmarks.append(bookmark)
                file.seek(0)
                json.dump(bookmarks, file)
        except (FileNotFoundError, json.JSONDecodeError):
            with open("bookmarks.json", "w") as file:
                json.dump([bookmark], file)

        QMessageBox.information(self, "Bookmark Added", f"Bookmark for '{title}' added.")

    def load_bookmarks(self):
        try:
            with open("bookmarks.json", "r") as file:
                bookmarks = json.load(file)
                for bookmark in bookmarks:
                    action = QAction(bookmark["title"], self)
                    action.triggered.connect(lambda url=bookmark["url"]: self.browser.setUrl(QUrl(url)))
                    self.findChild(QMenu, "Bookmarks").addAction(action)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

def main():
    app = QApplication(sys.argv)
    browser = Browser()
    browser.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()