from PyQt5.QtWidgets import QApplication
import sys

from ui.main_window import MainWindow


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet("""
        QMainWindow {
            background-color: #1e1e1e;
        }

        QTableWidget {
            background-color: #2b2b2b;
            color: white;
        }

        QPushButton {
            background-color: #3c3f41;
            color: white;
            padding: 6px;
        }

        QLineEdit {
            background-color: #2b2b2b;
            color: white;
        }""")

    window = MainWindow()
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()