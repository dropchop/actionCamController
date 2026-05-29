"""webui — Flask multi-camera controller for Larkfly / iCatch cameras.

Run as a script: ``python3 webui/app.py`` (app.py adds the repo root to
sys.path). This package is intentionally NOT part of the installable
``larkfly`` distribution — see ``pyproject.toml``, which packages only
``larkfly``.

Keep this file: it is the package marker that lets ``app.py`` do
``from webui.worker import ...``. Deleting it breaks that import.
"""
