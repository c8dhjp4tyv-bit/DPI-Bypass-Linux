"""GTK4/libadwaita olmadan GUI mantığını sınamak için asgari sahte 'gi'.

Arayüz kodunun görsel kısmı test edilmez; test edilen şey karar mantığıdır:
hangi erişim hatasında hangi banner gösteriliyor, ölçüm sonucu nasıl
biçimleniyor. Bunun için widget'ların yalnızca çağrılan yüzeyi taklit edilir.
"""

from __future__ import annotations

import sys
import types


class StubWidget:
    """Her çağrıyı kabul eden, ayarlanan değerleri saklayan sahte widget."""

    def __init__(self, **kwargs) -> None:
        self._props = dict(kwargs)
        self.children: list = []
        self.css: list[str] = []

    # -- Gtk/Adw yüzeyi ---------------------------------------------------
    def set_subtitle(self, text): self._props["subtitle"] = text
    def get_subtitle(self): return self._props.get("subtitle", "")
    def set_title(self, text): self._props["title"] = text
    def get_title(self): return self._props.get("title", "")
    def set_label(self, text): self._props["label"] = text
    def get_label(self): return self._props.get("label", "")
    def set_visible(self, value): self._props["visible"] = bool(value)
    def get_visible(self): return self._props.get("visible", True)
    def set_active(self, value): self._props["active"] = bool(value)
    def get_active(self): return self._props.get("active", False)
    def set_sensitive(self, value): self._props["sensitive"] = bool(value)
    def set_value(self, value): self._props["value"] = value
    def get_value(self): return self._props.get("value", 0)
    def set_selected(self, index): self._props["selected"] = index
    def get_selected(self): return self._props.get("selected", 0)
    def set_model(self, model): self._props["model"] = model
    def set_text(self, text): self._props["text"] = text
    def get_text(self): return self._props.get("text", "")
    def add(self, child): self.children.append(child)
    def remove(self, child):
        if child in self.children:
            self.children.remove(child)
    def append(self, child): self.children.append(child)
    def add_row(self, child): self.children.append(child)
    def add_suffix(self, child): self.children.append(child)
    def add_css_class(self, name): self.css.append(name)
    def remove_css_class(self, name):
        if name in self.css:
            self.css.remove(name)
    def set_activatable_widget(self, widget): self._props["activatable"] = widget
    def connect(self, *args, **kwargs): return 1
    def disconnect(self, *args): return None
    def set_child(self, child): self.children.append(child)
    def add_overlay(self, child): self.children.append(child)
    def add_titled_with_icon(self, child, *args): self.children.append(child)
    def add_top_bar(self, child): self.children.append(child)
    def add_bottom_bar(self, child): self.children.append(child)
    def set_content(self, child): self.children.append(child)
    def add_toast(self, toast): self.children.append(toast)
    def set_from_icon_name(self, name): self._props["icon"] = name
    def set_spinning(self, value): self._props["spinning"] = value
    def get_visible_child_name(self): return self._props.get("page", "durum")
    def add_action(self, action): self.children.append(action)
    def set_size_request(self, *args): return None
    def set_default_size(self, *args): return None
    def get_width(self): return 900
    def set_reveal(self, value): self._props["reveal"] = value
    def get_vadjustment(self): return StubWidget()
    def get_upper(self): return 0
    def get_page_size(self): return 0
    def get_clipboard(self): return StubWidget()
    def set(self, value): self._props["clipboard"] = value
    def present(self, *args): self._props["presented"] = True

    def __getattr__(self, name):
        # Taklit edilmeyen her çağrı sessizce yutulur.
        def _noop(*args, **kwargs):
            return None
        return _noop


class StubNamespace(types.SimpleNamespace):
    """Adw/Gtk/Gio/GLib gibi ad alanları: her isim bir StubWidget sınıfı."""

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        created = type(name, (StubWidget,), {})
        setattr(self, name, created)
        return created


def install() -> None:
    if "gi" in sys.modules:
        return
    adw = StubNamespace()
    gtk = StubNamespace()
    gio = StubNamespace()
    glib = StubNamespace()

    # Kod bu üç sabiti okur.
    gtk.Align = types.SimpleNamespace(CENTER=0, START=1, END=2, FILL=3)
    gtk.Orientation = types.SimpleNamespace(VERTICAL=0, HORIZONTAL=1)
    gtk.Justification = types.SimpleNamespace(CENTER=0)
    gtk.WrapMode = types.SimpleNamespace(WORD_CHAR=0)
    gtk.License = types.SimpleNamespace(GPL_3_0=0)
    gtk.Image.new_from_icon_name = staticmethod(lambda name: StubWidget())
    adw.ViewSwitcherPolicy = types.SimpleNamespace(WIDE=0)
    glib.timeout_add_seconds = staticmethod(lambda *args, **kwargs: 1)
    glib.idle_add = staticmethod(lambda func, *args: func(*args))
    glib.get_user_config_dir = staticmethod(lambda: "/tmp")
    glib.Error = type("Error", (Exception,), {})

    repository = types.ModuleType("gi.repository")
    repository.Adw = adw
    repository.Gtk = gtk
    repository.Gio = gio
    repository.GLib = glib
    repository.Gdk = StubNamespace()

    gi_module = types.ModuleType("gi")
    gi_module.require_version = lambda *args, **kwargs: None
    gi_module.repository = repository
    sys.modules["gi"] = gi_module
    sys.modules["gi.repository"] = repository
