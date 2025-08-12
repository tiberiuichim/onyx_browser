virtualenv .venv
.venv/bin/pip install uv
uv init .
.venv/bin/playwright install
uv add playwright
