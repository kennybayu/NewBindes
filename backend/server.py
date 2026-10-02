import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import APIRouter, FastAPI
from fastapi.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
from lib.db import client, db, ensure_indexes  # noqa: E402
from routers import activities, auth, dashboard, laporan, payments, tenants  # noqa: E402


# Startup runs before the yield, shutdown after it. Add your own setup/teardown here.
@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.index_task = asyncio.create_task(ensure_indexes())  # background: a big index build must not block boot
    yield
    client.close()


# Create the main app without a prefix
app = FastAPI(lifespan=lifespan)

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")


@api_router.get("/")
async def health():
    """Health check untuk readiness probe. Sengaja tidak membocorkan data apa pun."""
    return {"status": "ok"}


# Include the router in the main app
api_router.include_router(auth.router)
api_router.include_router(tenants.router)
api_router.include_router(payments.router)
api_router.include_router(dashboard.router)
api_router.include_router(laporan.router)
api_router.include_router(activities.router)
app.include_router(api_router)


@app.middleware("http")
async def csrf_dan_security_headers(request, call_next):
    """Proteksi CSRF + header pengerasan standar.

    Cookie sesi diset `SameSite=Lax`, TETAPI ingress/CDN di depan aplikasi
    menulisnya ulang menjadi `SameSite=None` (terpantau pada deployment ini),
    sehingga proteksi SameSite tidak bisa diandalkan.

    Pertahanan yang dipakai (tidak bergantung pada header Host, karena di balik
    ingress `Host` bukan domain publik):

    1. `Sec-Fetch-Site: cross-site` -> tolak. Header ini diisi OLEH BROWSER dan
       termasuk forbidden header name, jadi tidak bisa dipalsukan halaman
       penyerang. Permintaan non-browser (curl, health check) tidak mengirimnya
       dan tetap diizinkan.
    2. Permintaan ber-body wajib `Content-Type: application/json`. Form HTML
       lintas situs hanya bisa mengirim urlencoded/multipart/text-plain, jadi
       jalur CSRF klasik ikut tertutup pada browser lama tanpa Sec-Fetch-Site.

    Dikombinasikan dengan CORS tanpa `allow_credentials`, fetch/XHR lintas
    origin juga tidak akan pernah menyertakan cookie sesi.
    """
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse(
                status_code=403,
                content={"detail": "Permintaan lintas situs ditolak (CSRF)"},
            )
        if request.headers.get("content-length") not in (None, "0"):
            ctype = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
            if ctype and ctype != "application/json":
                return JSONResponse(
                    status_code=415,
                    content={"detail": "Content-Type harus application/json"},
                )

    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=()")
    return response

# CORS: frontend memanggil path relatif /api lewat origin yang sama, jadi CORS
# sebetulnya tidak diperlukan. Bila CORS_ORIGINS masih "*", kredensial TIDAK
# boleh diizinkan — wildcard + allow_credentials membuat origin mana pun bisa
# memantulkan permintaan bercookie. Set CORS_ORIGINS ke daftar origin eksplisit
# (dipisah koma) bila memang perlu memanggil API dari domain lain.
_origins = [o.strip() for o in os.environ.get('CORS_ORIGINS', '*').split(',') if o.strip()]
_wildcard = "*" in _origins

app.add_middleware(
    CORSMiddleware,
    allow_credentials=not _wildcard,
    allow_origins=_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("server:app", host="0.0.0.0", port=port)
