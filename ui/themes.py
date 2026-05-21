"""
themes.py — NetSentinel UI theme definitions
Two themes: DARK (slate/indigo) and LIGHT (warm white)
"""

# ══════════════════════════════════════════════════════════════
#  DARK THEME  —  Slate + Indigo + Cyan accent
#  Inspired by: Linear, Vercel, Arc browser
# ══════════════════════════════════════════════════════════════
DARK = {
    # Surfaces
    "bg_window":   "#0f1117",
    "bg_sidebar":  "#13151c",
    "bg_surface":  "#1a1d27",
    "bg_card":     "#1e2130",
    "bg_hover":    "#252a3a",
    "bg_active":   "#2a3050",
    "bg_input":    "#1a1d27",
    "bg_overlay":  "#0f1117ee",

    # Borders
    "border":      "#2e3347",
    "border_soft": "#252840",

    # Text
    "text_primary":  "#e8eaf0",
    "text_secondary":"#8b90a8",
    "text_muted":    "#4d5472",
    "text_on_accent":"#ffffff",

    # Accent — Indigo/Cyan
    "accent":        "#6366f1",       # indigo
    "accent_hover":  "#7c7ff5",
    "accent_glow":   "#6366f133",
    "accent2":       "#06b6d4",       # cyan
    "accent2_glow":  "#06b6d433",

    # Semantic
    "success":       "#22c55e",
    "success_bg":    "#052015",
    "warning":       "#f59e0b",
    "warning_bg":    "#1f1400",
    "danger":        "#f43f5e",
    "danger_bg":     "#1f0510",
    "info":          "#38bdf8",
    "info_bg":       "#011f30",

    # Protocol colours
    "proto_tcp":     "#6366f1",
    "proto_udp":     "#06b6d4",
    "proto_other":   "#f59e0b",

    # Table
    "row_even":      "#1a1d27",
    "row_odd":       "#1e2130",
    "row_selected":  "#2a3050",

    "is_dark": True,
}

# ══════════════════════════════════════════════════════════════
#  LIGHT THEME  —  Warm White + Violet + Teal accent
#  Inspired by: macOS Ventura, Notion, Linear light
# ══════════════════════════════════════════════════════════════
LIGHT = {
    # Surfaces
    "bg_window":   "#f5f5f7",
    "bg_sidebar":  "#ffffff",
    "bg_surface":  "#ffffff",
    "bg_card":     "#ffffff",
    "bg_hover":    "#f0f0f5",
    "bg_active":   "#ebebf5",
    "bg_input":    "#f5f5f7",
    "bg_overlay":  "#f5f5f7ee",

    # Borders
    "border":      "#e2e2ea",
    "border_soft": "#ededf5",

    # Text
    "text_primary":  "#111118",
    "text_secondary":"#5c5c72",
    "text_muted":    "#aaaabc",
    "text_on_accent":"#ffffff",

    # Accent — Violet/Teal
    "accent":        "#7c3aed",       # violet
    "accent_hover":  "#6d28d9",
    "accent_glow":   "#7c3aed22",
    "accent2":       "#0d9488",       # teal
    "accent2_glow":  "#0d948822",

    # Semantic
    "success":       "#16a34a",
    "success_bg":    "#f0fdf4",
    "warning":       "#d97706",
    "warning_bg":    "#fffbeb",
    "danger":        "#dc2626",
    "danger_bg":     "#fef2f2",
    "info":          "#0284c7",
    "info_bg":       "#f0f9ff",

    # Protocol colours
    "proto_tcp":     "#7c3aed",
    "proto_udp":     "#0d9488",
    "proto_other":   "#d97706",

    # Table
    "row_even":      "#ffffff",
    "row_odd":       "#fafafa",
    "row_selected":  "#ebebf5",

    "is_dark": False,
}


def get_stylesheet(T: dict) -> str:
    """Generate full Qt stylesheet from a theme dict."""
    shadow = "rgba(0,0,0,0.35)" if T["is_dark"] else "rgba(0,0,0,0.08)"

    return f"""
/* ── Global ──────────────────────────────────────────── */
QMainWindow, QWidget {{
    background: {T['bg_window']};
    color: {T['text_primary']};
    font-family: 'SF Pro Display', 'Segoe UI Variable', 'Segoe UI', system-ui, sans-serif;
    font-size: 13px;
}}

/* ── Tables ──────────────────────────────────────────── */
QTableWidget {{
    background: {T['bg_surface']};
    alternate-background-color: {T['row_odd']};
    color: {T['text_primary']};
    gridline-color: transparent;
    border: 1px solid {T['border']};
    border-radius: 12px;
    selection-background-color: {T['row_selected']};
    selection-color: {T['text_primary']};
    outline: none;
}}
QTableWidget::item {{
    padding: 0 10px;
    border: none;
}}
QTableWidget::item:selected {{
    background: {T['row_selected']};
    color: {T['text_primary']};
}}
QHeaderView::section {{
    background: {T['bg_card']};
    color: {T['text_muted']};
    border: none;
    border-bottom: 1px solid {T['border']};
    padding: 8px 12px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.8px;
    text-transform: uppercase;
}}
QHeaderView::section:first {{
    border-top-left-radius: 12px;
}}
QHeaderView::section:last {{
    border-top-right-radius: 12px;
}}

/* ── Scrollbars ──────────────────────────────────────── */
QScrollBar:vertical {{
    background: transparent;
    width: 6px;
    margin: 4px 2px;
}}
QScrollBar::handle:vertical {{
    background: {T['border']};
    border-radius: 3px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{
    background: {T['text_muted']};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QScrollBar:horizontal {{
    background: transparent;
    height: 6px;
    margin: 2px 4px;
}}
QScrollBar::handle:horizontal {{
    background: {T['border']};
    border-radius: 3px;
}}

/* ── Text areas ──────────────────────────────────────── */
QTextEdit {{
    background: {T['bg_input']};
    color: {T['text_primary']};
    border: 1px solid {T['border']};
    border-radius: 10px;
    padding: 10px 12px;
    font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', 'Consolas', monospace;
    font-size: 12px;
    line-height: 1.6;
    selection-background-color: {T['accent_glow']};
}}

/* ── Line edits ──────────────────────────────────────── */
QLineEdit {{
    background: {T['bg_input']};
    color: {T['text_primary']};
    border: 1.5px solid {T['border']};
    border-radius: 8px;
    padding: 7px 12px;
    font-size: 13px;
    selection-background-color: {T['accent_glow']};
}}
QLineEdit:focus {{
    border-color: {T['accent']};
    background: {T['bg_surface']};
}}
QLineEdit::placeholder {{
    color: {T['text_muted']};
}}

/* ── Combo boxes ─────────────────────────────────────── */
QComboBox {{
    background: {T['bg_input']};
    color: {T['text_primary']};
    border: 1.5px solid {T['border']};
    border-radius: 8px;
    padding: 6px 12px;
    font-size: 13px;
    min-width: 90px;
}}
QComboBox:hover {{
    border-color: {T['text_muted']};
}}
QComboBox:focus {{
    border-color: {T['accent']};
}}
QComboBox::drop-down {{
    border: none;
    padding-right: 10px;
}}
QComboBox::down-arrow {{
    width: 10px;
    height: 10px;
}}
QComboBox QAbstractItemView {{
    background: {T['bg_card']};
    color: {T['text_primary']};
    border: 1px solid {T['border']};
    border-radius: 8px;
    padding: 4px;
    selection-background-color: {T['bg_hover']};
    outline: none;
}}

/* ── Scroll areas ────────────────────────────────────── */
QScrollArea {{
    border: none;
    background: transparent;
}}

/* ── Tooltips ────────────────────────────────────────── */
QToolTip {{
    background: {T['bg_card']};
    color: {T['text_primary']};
    border: 1px solid {T['border']};
    border-radius: 6px;
    padding: 5px 10px;
    font-size: 12px;
}}

/* ── Message Box ─────────────────────────────────────── */
QMessageBox {{
    background: {T['bg_card']};
}}
QMessageBox QLabel {{
    color: {T['text_primary']};
    font-size: 13px;
}}
"""