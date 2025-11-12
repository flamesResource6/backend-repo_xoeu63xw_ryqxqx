import os
import secrets
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from database import db, create_document, get_documents
from schemas import User, Report, Session

app = FastAPI(title="SheSecure API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------- Utility --------------------

def collection(name: str):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    return db[name]

# -------------------- Auth & Profiles --------------------

class LoginRequest(BaseModel):
    name: str
    phone: str
    email: str

class SignupRequest(BaseModel):
    name: str
    phone: str
    email: str
    address: Optional[str] = None
    state: Optional[str] = None
    emergency_contacts: List[str] = []
    photo_url: Optional[str] = None
    language: str = "en"

class SessionResponse(BaseModel):
    token: str
    user_id: str

@app.post("/api/login", response_model=SessionResponse)
def login(payload: LoginRequest):
    users = list(collection("user").find({"email": payload.email, "phone": payload.phone}))
    if not users:
        raise HTTPException(status_code=404, detail="Account not found. Please create an account.")
    user = users[0]
    token = secrets.token_hex(16)
    create_document("session", {"user_id": str(user.get("_id")), "token": token})
    return {"token": token, "user_id": str(user.get("_id"))}

@app.post("/api/signup", response_model=SessionResponse)
def signup(payload: SignupRequest):
    # prevent duplicate email/phone
    exists = collection("user").find_one({"$or": [{"email": payload.email}, {"phone": payload.phone}]})
    if exists:
        raise HTTPException(status_code=400, detail="User with this email or phone already exists")
    user = User(**payload.model_dump())
    user_id = create_document("user", user)
    token = secrets.token_hex(16)
    create_document("session", {"user_id": user_id, "token": token})
    return {"token": token, "user_id": user_id}

@app.get("/api/profile/{user_id}")
def get_profile(user_id: str):
    u = collection("user").find_one({"_id": {"$oid": user_id}})
    # Fallback when ObjectId helper not available in this runtime: try direct string match stored earlier
    if not u:
        u = collection("user").find_one({"_id": user_id}) or collection("user").find_one({"_id": {"$in": [user_id]}})
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    u["_id"] = str(u.get("_id"))
    return u

class UpdateProfile(BaseModel):
    name: Optional[str] = None
    address: Optional[str] = None
    state: Optional[str] = None
    photo_url: Optional[str] = None
    emergency_contacts: Optional[List[str]] = None
    language: Optional[str] = None

@app.put("/api/profile/{user_id}")
def update_profile(user_id: str, payload: UpdateProfile):
    data = {k: v for k, v in payload.model_dump().items() if v is not None}
    res = collection("user").update_one({"_id": user_id}, {"$set": data})
    if res.matched_count == 0:
        # try alt matching
        res = collection("user").update_one({"_id": {"$oid": user_id}}, {"$set": data})
        if res.matched_count == 0:
            raise HTTPException(status_code=404, detail="User not found")
    return {"updated": True}

@app.delete("/api/profile/{user_id}")
def delete_account(user_id: str):
    collection("user").delete_one({"_id": user_id})
    collection("user").delete_many({"user_id": user_id})
    return {"deleted": True}

# -------------------- Unsafe Reports --------------------

class ReportRequest(BaseModel):
    lat: float
    lng: float
    description: Optional[str] = None
    photo_url: Optional[str] = None
    severity: int = 1
    user_id: Optional[str] = None

@app.post("/api/report")
def create_report(payload: ReportRequest):
    report_id = create_document("report", Report(**payload.model_dump()))
    return {"id": report_id}

@app.get("/api/reports")
def list_reports(lat: Optional[float] = None, lng: Optional[float] = None, radius_km: float = 5):
    # naive: return last 200 reports. A proper geo query would use geo indexes.
    docs = list(collection("report").find().sort("created_at", -1).limit(200))
    for d in docs:
        d["_id"] = str(d.get("_id"))
    return docs

# -------------------- Routing & Safety --------------------

class RouteQuery(BaseModel):
    origin: List[float]  # [lat, lng]
    destination: List[float]
    timestamp: Optional[int] = None

@app.post("/api/route-safety")
def route_safety(payload: RouteQuery):
    # Placeholder for external API integration: Google Places/Maps could be called here.
    # We'll simulate POI density using nearby reports and time of day component.
    import math, time

    now = payload.timestamp or int(time.time())
    hour = (now // 3600) % 24
    time_factor = 0.7 if hour >= 20 or hour <= 5 else 1.0

    # Compute simple densities from reports near the midpoint
    mid_lat = (payload.origin[0] + payload.destination[0]) / 2
    mid_lng = (payload.origin[1] + payload.destination[1]) / 2

    reports = list(collection("report").find())
    unsafe_reports = 0
    safe_reports = 0
    for r in reports:
        d = math.hypot((r.get("lat", 0) - mid_lat), (r.get("lng", 0) - mid_lng))
        if d < 0.05:  # approx ~5km depending on latitude (rough)
            s = int(r.get("severity", 1))
            unsafe_reports += s
        elif d < 0.1:
            unsafe_reports += 1
        else:
            safe_reports += 1

    poi_density = max(0.0, min(1.0, (safe_reports % 20) / 20))  # fake signal 0..1
    sr_norm = max(0.0, min(1.0, safe_reports / 50))
    ur_norm = max(0.0, min(1.0, unsafe_reports / 50))

    score = (0.6 * poi_density + 0.3 * sr_norm - 0.5 * ur_norm) * time_factor
    safety = "safe" if score >= 0.5 else ("moderate" if score >= 0.25 else "dangerous")

    reason = []
    if time_factor < 1:
        reason.append("Late hours reduce safety")
    if ur_norm > 0.2:
        reason.append("Multiple unsafe reports nearby")
    if poi_density > 0.5:
        reason.append("Crowded places increase safety")

    # Return a mocked polyline path (straight line) for demo
    path = [
        {"lat": payload.origin[0], "lng": payload.origin[1]},
        {"lat": mid_lat, "lng": mid_lng},
        {"lat": payload.destination[0], "lng": payload.destination[1]},
    ]

    return {
        "score": score,
        "safety": safety,
        "reasons": reason,
        "path": path,
    }

# -------------------- SOS via Twilio (stub) --------------------

class SOSRequest(BaseModel):
    user_id: str
    name: str
    phone: str
    lat: float
    lng: float

@app.post("/api/sos")
def send_sos(payload: SOSRequest):
    # Integrate Twilio if credentials available, else simulate success
    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    from_number = os.getenv("TWILIO_PHONE_NUMBER")

    message = (
        f"⚠️ EMERGENCY ALERT! {payload.name} needs help immediately. "
        f"Current location: https://maps.google.com/?q={payload.lat},{payload.lng}. "
        f"Contact: {payload.phone}."
    )

    # Fetch user's emergency contacts
    u = collection("user").find_one({"_id": payload.user_id}) or collection("user").find_one({"_id": {"$oid": payload.user_id}})
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    contacts = u.get("emergency_contacts", [])[:4]

    sent_to = []
    if account_sid and auth_token and from_number:
        try:
            from twilio.rest import Client  # type: ignore
            client = Client(account_sid, auth_token)
            for c in contacts:
                c = str(c)
                if not c:
                    continue
                res = client.messages.create(body=message, from_=from_number, to=c)
                sent_to.append({"to": c, "sid": res.sid})
        except Exception as e:
            # Fall back to simulated send
            sent_to = [{"to": c, "sid": "simulated"} for c in contacts]
    else:
        # Simulate sending in this environment
        sent_to = [{"to": c, "sid": "simulated"} for c in contacts]

    return {"ok": True, "sent": sent_to, "message": message}

# -------------------- Health --------------------

@app.get("/")
def root():
    return {"message": "SheSecure backend is running"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available" if db is None else "✅ Connected",
    }
    try:
        if db is not None:
            response["collections"] = db.list_collection_names()
    except Exception as e:
        response["database"] = f"⚠️ {str(e)[:60]}"
    return response

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
