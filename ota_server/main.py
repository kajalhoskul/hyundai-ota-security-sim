"""OTA server: manages signed firmware campaigns for a simulated vehicle
fleet. Models the manufacturer side of a UNECE R156 Software Update
Management System (SUMS).

Run with:
    uvicorn ota_server.main:app --port 8100
"""
import base64
import os

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates

from . import crypto
from .store import FirmwarePackage, OtaStore
from .versioning import is_newer

BASE_DIR = os.path.dirname(__file__)
KEYS_DIR = os.path.join(BASE_DIR, "..", "keys")
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "manufacturer_private.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "manufacturer_public.pem")

if not os.path.exists(PRIVATE_KEY_PATH):
    raise SystemExit(
        "No manufacturer keypair found. Run `python scripts/setup_keys.py` first."
    )

private_key = crypto.load_private_key(PRIVATE_KEY_PATH)
public_key = crypto.load_public_key(PUBLIC_KEY_PATH)

store = OtaStore()
app = FastAPI(title="Hyundai OTA Update Server (demo)")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


@app.post("/admin/vehicles/register")
async def register_vehicle(request: Request):
    body = await request.json()
    store.add_vehicle(body["vin"], body["model"], body["region"], body["current_version"])
    vehicle = store.vehicles[body["vin"]]
    return {"status": "registered", "current_version": vehicle.current_version}


@app.post("/admin/publish")
async def publish_firmware(request: Request):
    """Simulates the manufacturer's secure build+sign pipeline: takes a raw
    firmware payload, computes its hash, signs it with the private key that
    only the manufacturer holds, and starts a campaign. A real
    implementation would run this inside a hardware security module, never
    on a machine reachable from the public internet.
    """
    body = await request.json()
    version = body["version"]
    model_scope = body["model"]
    regions = body.get("regions") or []
    is_buggy = bool(body.get("is_buggy", False))
    firmware_bytes = base64.b64decode(body["firmware_b64"])

    signature_b64 = crypto.sign(private_key, firmware_bytes)
    pkg = FirmwarePackage(
        version=version,
        model_scope=model_scope,
        bytes_=firmware_bytes,
        sha256=crypto.sha256_hex(firmware_bytes),
        signature_b64=signature_b64,
        is_buggy=is_buggy,
    )
    store.publish_firmware(pkg, regions)
    return {"status": "published", "version": version, "sha256": pkg.sha256}


@app.get("/ota/check-in")
async def check_in(vin: str):
    vehicle = store.vehicles.get(vin)
    if not vehicle:
        raise HTTPException(status_code=404, detail="Vehicle not registered")

    campaign = store.active_campaign_for(vehicle)
    if not campaign or not is_newer(campaign["version"], vehicle.current_version):
        return {"update_available": False}

    pkg = store.firmware[campaign["version"]]
    return {
        "update_available": True,
        "version": pkg.version,
        "sha256": pkg.sha256,
        "signature": pkg.signature_b64,
        "download_url": f"/ota/firmware/{pkg.version}",
    }


@app.get("/ota/firmware-meta/{version}")
async def firmware_meta(version: str):
    # Models an attacker who has obtained an OLD, genuinely-signed package
    # (e.g. pulled from a public mirror, a dealer tool, or another vehicle
    # that hasn't updated yet) -- not a server compromise. The signature
    # and hash here are 100% authentic; only the *version* is stale.
    pkg = store.firmware.get(version)
    if not pkg:
        raise HTTPException(status_code=404, detail="Unknown firmware version")
    return {"version": pkg.version, "sha256": pkg.sha256, "signature": pkg.signature_b64}


@app.get("/ota/firmware/{version}")
async def download_firmware(version: str):
    pkg = store.firmware.get(version)
    if not pkg:
        raise HTTPException(status_code=404, detail="Unknown firmware version")
    return Response(content=pkg.bytes_, media_type="application/octet-stream")


@app.post("/ota/report")
async def report(request: Request):
    body = await request.json()
    vin, version, status, reason = body["vin"], body["version"], body["status"], body.get("reason", "")
    store.log_event(vin, status, version, reason)
    if status == "installed":
        vehicle = store.vehicles.get(vin)
        if vehicle:
            vehicle.current_version = version
    return {"status": "logged"}


@app.get("/admin/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(request, "dashboard.html", {})


@app.get("/admin/stats.json")
async def stats():
    return JSONResponse({
        "totals": store.totals(),
        "version_distribution": store.version_distribution(),
        "rejected_by_reason": store.rejected_by_reason(),
        "recent_events": store.recent_events(20),
    })


@app.get("/admin/public-key")
async def get_public_key():
    # Exposed only so the demo's vehicle clients can load the SAME pinned
    # key a real vehicle would have embedded at manufacture time. A real
    # vehicle never fetches this over the network at runtime.
    with open(PUBLIC_KEY_PATH) as f:
        return {"public_key_pem": f.read()}
