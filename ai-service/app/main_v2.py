"""Extended NTShield Brain application with bounded investigation and code-security routes."""

from .main import app
from .routes_code_scan import router as code_scan_router
from .routes_v2 import router

app.include_router(router)
app.include_router(code_scan_router)
