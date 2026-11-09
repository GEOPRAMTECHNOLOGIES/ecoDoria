"""
EcoDoria — Environmental Patrol
Production-oriented Flask/MongoDB starter. Review README security/legal checklist before launch.
"""
import os, io, re, csv, json, uuid, hashlib, secrets, base64, logging
from datetime import datetime, timedelta, timezone
from functools import wraps
from bson import ObjectId
from flask import Flask, request, session, redirect, url_for, render_template, jsonify, abort, send_file, make_response, flash
from dotenv import load_dotenv
from pymongo import MongoClient, ASCENDING, DESCENDING, GEOSPHERE
from pymongo.errors import DuplicateKeyError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image, ImageOps, ImageDraw, ImageFont
from cryptography.fernet import Fernet, InvalidToken
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from shapely.geometry import shape, Point, mapping
from shapely.ops import transform
from pyproj import Transformer
import requests
import smtplib
import hmac
from email.message import EmailMessage
from email.utils import parseaddr
from html import unescape
from werkzeug.security import generate_password_hash

load_dotenv()
logging.basicConfig(level=logging.INFO)
app=Flask(__name__)
app.config.update(SECRET_KEY=os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32),
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE","true").lower()=="true",
                  SESSION_COOKIE_SAMESITE="Lax", MAX_CONTENT_LENGTH=8*1024*1024)
csrf=CSRFProtect(app)
limiter=Limiter(get_remote_address,app=app,default_limits=["300 per hour"],storage_uri="memory://")
MONGO_URI=os.getenv("MONGODB_URI","")
client=MongoClient(MONGO_URI,serverSelectionTimeoutMS=5000) if MONGO_URI else None
db=client[os.getenv("MONGODB_DB","ecodoria")] if client is not None else None
MAX_GPS=float(os.getenv("GPS_MAX_ACCURACY_M","50"))
REWARD=int(os.getenv("REWARD_AMOUNT_KES","50"))
FERNET=None
try:
    key=os.getenv("ENCRYPTION_KEY")
    FERNET=Fernet(key.encode()) if key else None
except Exception: logging.exception("Invalid ENCRYPTION_KEY; encrypted features disabled")

def now(): return datetime.now(timezone.utc)
def oid(v):
    try: return ObjectId(str(v))
    except Exception: return None
def col(name):
    if db is None: raise RuntimeError("MONGODB_URI is not configured")
    return db[name]
def audit(action, target=None, detail=None):
    if db is not None:
        col("audit_log").insert_one({"actor_id":session.get("uid"),"role":session.get("role"),
          "action":action,"target":str(target) if target else None,"detail":detail or {},
          "ip":request.headers.get("X-Forwarded-For",request.remote_addr),"at":now()})
def require(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapped(*a,**kw):
            if not session.get("uid"): return redirect(url_for("login"))
            if roles and session.get("role") not in roles: abort(403)
            return fn(*a,**kw)
        return wrapped
    return deco
def user_doc():
    return col("users").find_one({"_id":oid(session.get("uid"))}) if session.get("uid") else None
def encrypt(value):
    if not FERNET: raise RuntimeError("ENCRYPTION_KEY is required for KYC")
    return FERNET.encrypt(value if isinstance(value,bytes) else str(value).encode())
def decrypt(value):
    if not FERNET: raise RuntimeError("ENCRYPTION_KEY unavailable")
    return FERNET.decrypt(value)
def send_sms(phone,msg):
    # Missing Africa's Talking credentials degrades to server log.
    if not os.getenv("AT_USERNAME") or not os.getenv("AT_API_KEY"):
        app.logger.info("SMS (not sent) to %s: %s",phone,msg); return False
    try:
        r=requests.post("https://api.africastalking.com/version1/messaging",headers={
          "apiKey":os.getenv("AT_API_KEY"),"Accept":"application/json"},
          data={"username":os.getenv("AT_USERNAME"),"to":phone,"message":msg,
                "from":os.getenv("AT_SENDER_ID") or ""},timeout=10)
        return r.ok
    except Exception: app.logger.exception("SMS failed"); return False
def send_email(to,subject,html):
    """Send email through authenticated SMTP; never silently claim delivery."""
    host=os.getenv("SMTP_HOST","").strip()
    username=os.getenv("SMTP_USERNAME","").strip()
    password=os.getenv("SMTP_PASSWORD","")
    sender=os.getenv("SMTP_FROM","").strip()
    try:
        port=int(os.getenv("SMTP_PORT","587"))
    except ValueError:
        app.logger.error("SMTP_PORT must be a valid integer")
        return False
    if not all((host,username,password,sender,to)):
        app.logger.warning("Email not sent: SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM and recipient are required")
        return False
    try:
        msg=EmailMessage()
        msg["Subject"]=subject
        msg["From"]=sender
        msg["To"]=to
        msg.set_content(re.sub(r"<[^>]+>"," ",unescape(html)).strip() or subject)
        msg.add_alternative(html,subtype="html")
        if port==465:
            with smtplib.SMTP_SSL(host,port,timeout=15) as server:
                server.login(username,password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(host,port,timeout=15) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(username,password)
                server.send_message(msg)
        return True
    except Exception:
        app.logger.exception("SMTP email delivery failed")
        return False

def create_indexes():
    """Run once at startup/deploy; safe to rerun."""
    if db is None: return
    for c in ("reports","layers"): col(c).create_index([("location","2dsphere")])
    col("users").create_index("phone",unique=True)
    col("images").create_index([("created_at",ASCENDING)])
    col("otp_codes").create_index("expires_at",expireAfterSeconds=0)
    col("reports").create_index([("photo_sha256",ASCENDING),("created_at",DESCENDING)])
    col("reports").create_index([("user_id",ASCENDING),("created_at",DESCENDING)])
    col("reports").create_index([("status",ASCENDING),("county",ASCENDING)])
    col("officers").create_index([("agency_id",ASCENDING),("counties",ASCENDING)])
    col("routing_rules").create_index([("category",ASCENDING),("county",ASCENDING),("layer_type",ASCENDING)],unique=True)
    col("images").create_index([("owner_id",ASCENDING),("kind",ASCENDING)])
    col("payouts").create_index([("user_id",ASCENDING),("created_at",DESCENDING)])
    col("counties").create_index("name",unique=True)
    col("layers").create_index([("county",ASCENDING),("layer_type",ASCENDING),("version",DESCENDING)])
    col("hotspots").create_index([("location","2dsphere")])
    col("audit_log").create_index([("at",DESCENDING)])
    col("otp_codes").create_index("phone")
    col("stk_transactions").create_index("checkout_request_id",sparse=True,unique=True)
    col("stk_transactions").create_index([("created_at",DESCENDING)])
    col("reports").create_index([("report_id",ASCENDING)],unique=True)

def image_bytes(raw, max_bytes=300_000, max_dim=1800, quality=78):
    if len(raw)>max_bytes: raise ValueError("Image exceeds 300KB")
    im=Image.open(io.BytesIO(raw)); im=ImageOps.exif_transpose(im).convert("RGB")
    im.thumbnail((max_dim,max_dim))
    out=io.BytesIO(); im.save(out,"JPEG",quality=quality,optimize=True)
    data=out.getvalue()
    if len(data)>max_bytes:
        out=io.BytesIO(); im.save(out,"JPEG",quality=55,optimize=True); data=out.getvalue()
    if len(data)>max_bytes: raise ValueError("Compressed image exceeds 300KB")
    return data
def store_image(raw, owner_id, kind, encrypted=False):
    data=image_bytes(raw)
    if encrypted: data=encrypt(data)
    return col("images").insert_one({"bytes":data,"content_type":"application/octet-stream" if encrypted else "image/jpeg",
       "owner_id":str(owner_id),"kind":kind,"encrypted":encrypted,"created_at":now(),
       "sha256":hashlib.sha256(data).hexdigest()}).inserted_id

def county_for(lon,lat):
    q={"active":True,"geometry":{"$geoIntersects":{"$geometry":{"type":"Point","coordinates":[lon,lat]}}}}
    return col("counties").find_one(q) or col("counties").find_one({"active":True,"name":"Unassigned"})
def geo_checks(lon,lat,county):
    hits=[]
    if not county: return hits
    for layer in col("layers").find({"county":county["name"],"active":True}):
        try:
            geom=shape(layer["geometry"])
            p=Point(lon,lat)
            # Configurable conservative buffers in metres via local UTM.
            if geom.intersects(p): hits.append({"type":layer["layer_type"],"hit":True,"feature":layer.get("feature_name","")})
            else:
                transformer=Transformer.from_crs("EPSG:4326",f"EPSG:{32600+int((lon+180)//6)+1}",always_xy=True)
                metric=transform(transformer.transform,geom)
                mp=transform(transformer.transform,p)
                buffer_m=float(col("settings").find_one({"key":"buffer_"+layer["layer_type"]}) or {}).get("value",30)
                if metric.distance(mp)<=buffer_m: hits.append({"type":layer["layer_type"],"hit":False,"within_buffer_m":buffer_m})
        except Exception: continue
    return hits
def fraud_score(user,accuracy,home_mismatch,lat,lon):
    score=0
    if accuracy>MAX_GPS: score+=35
    if home_mismatch: score+=20
    recent=col("reports").count_documents({"user_id":user["_id"],"created_at":{"$gte":now()-timedelta(hours=1)}})
    if recent>=3: score+=25
    score+=max(0,10-int(user.get("reputation",0)/10))
    return min(100,score)
def route_report(report):
    county=report.get("county")
    rule=col("routing_rules").find_one({"category":report["category"],"county":county,"layer_type":report.get("primary_layer","")})
    if not rule: rule=col("routing_rules").find_one({"category":report["category"],"county":county,"layer_type":"*"})
    if not rule: return
    agency=col("agencies").find_one({"_id":rule["agency_id"]})
    if not agency: return
    for officer in col("officers").find({"agency_id":agency["_id"],"counties":county}):
        token=secrets.token_urlsafe(32)
        col("officer_links").insert_one({"token_hash":hashlib.sha256(token.encode()).hexdigest(),
          "officer_id":officer["_id"],"report_id":report["_id"],"expires_at":now()+timedelta(hours=48),"used":False})
        link=(os.getenv("PUBLIC_BASE_URL","https://example.com")+"/o/"+token)
        send_sms(officer.get("phone",""),f"EcoDoria: new alleged {report['category']} report in {county}. Review: {link}")
        if officer.get("email"): send_email(officer["email"],"New EcoDoria report",f'<p>New alleged report. <a href="{link}">Open securely</a></p>')
    col("reports").update_one({"_id":report["_id"]},{"$set":{"agency_id":agency["_id"],"agency_name":agency["name"]}})

@app.before_request
def ensure_db():
    if db is None and request.endpoint not in ("health","static"):
        # Render a helpful setup message rather than crash obscurely.
        pass
@app.get("/health")
def health(): return jsonify(ok=True,mongodb=bool(db))
@app.get("/")
def index():
    wards=list(col("reports").aggregate([{"$match":{"status":{"$in":["Verified","Pending"]}}},
      {"$group":{"_id":{"county":"$county","ward":"$ward"},"total":{"$sum":1}}},
      {"$project":{"_id":0,"county":"$_id.county","ward":"$_id.ward","total":1}}])) if db is not None else []
    return render_template("index.html",wards=wards,brand=brand())
def brand():
    county=request.args.get("county") or session.get("county")
    cfg=col("settings").find_one({"key":"branding_"+str(county)}) if db is not None and county else None
    return {"name":cfg.get("name") if cfg else "EcoDoria","subtitle":"Environmental Patrol",
            "accent":cfg.get("accent","#16834a") if cfg else "#16834a","logo":cfg.get("logo") if cfg else None}
@app.get("/login")
def login(): return render_template("login.html",brand=brand())
@app.post("/auth/request-otp")
@limiter.limit("5 per hour")
def request_otp():
    phone=re.sub(r"\s+","",request.form.get("phone",""))
    if not re.fullmatch(r"\+?[0-9]{9,15}",phone): abort(400,"Invalid phone")
    code=f"{secrets.randbelow(1000000):06d}"
    col("otp_codes").insert_one({"phone":phone,"code_hash":generate_password_hash(code),"expires_at":now()+timedelta(minutes=5)})
    send_sms(phone,f"Your EcoDoria sign-in code is {code}. It expires in 5 minutes.")
    # In development only, OTP is logged; do not expose it in production.
    if app.debug: return jsonify(message="OTP sent",development_code=code)
    return jsonify(message="OTP sent")
@app.post("/auth/verify-otp")
@limiter.limit("10 per hour")
def verify_otp():
    phone=request.form.get("phone",""); code=request.form.get("code","")
    otp=col("otp_codes").find_one({"phone":phone,"expires_at":{"$gt":now()}},sort=[("_id",-1)])
    if not otp or not check_password_hash(otp["code_hash"],code): abort(401,"Invalid or expired OTP")
    col("otp_codes").delete_many({"phone":phone})
    u=col("users").find_one({"phone":phone})
    if not u:
        uid=col("users").insert_one({"phone":phone,"role":"citizen","tier":0,"level":"Recruit","wallet_balance":0,
          "reputation":0,"confirmed_reports":0,"suspended":False,"created_at":now()}).inserted_id
        u=col("users").find_one({"_id":uid})
    if u.get("suspended"): abort(403,"Account suspended")
    session.clear(); session.update(uid=str(u["_id"]),role=u.get("role","citizen"))
    return redirect(url_for("dashboard"))
@app.get("/logout")
def logout(): session.clear(); return redirect(url_for("index"))
@app.get("/dashboard")
@require("citizen","admin")
def dashboard():
    u=user_doc()
    reports=list(col("reports").find({"user_id":u["_id"]}).sort("created_at",-1).limit(100))
    return render_template("dashboard.html",u=u,reports=reports,brand=brand())
@app.get("/verify")
@require("citizen")
def verify(): return render_template("verify.html",brand=brand())
@app.post("/verify")
@require("citizen")
@limiter.limit("3 per day")
def verify_submit():
    u=user_doc()
    if u.get("tier",0)>=1: return redirect(url_for("dashboard"))
    consent=request.form.get("consent")=="yes"
    if not consent: abort(400,"Consent is required")
    try:
        selfie=base64.b64decode(request.form["selfie"].split(",")[-1])
        idphoto=base64.b64decode(request.form["idphoto"].split(",")[-1])
        sig=base64.b64decode(request.form["signature"].split(",")[-1])
        ids=encrypt(request.form.get("id_number",""))
        sid=store_image(selfie,u["_id"],"kyc_selfie",True)
        iid=store_image(idphoto,u["_id"],"kyc_id",True)
        signid=store_image(sig,u["_id"],"kyc_signature",True)
    except Exception as e: abort(400,str(e))
    loc={"type":"Point","coordinates":[float(request.form.get("lng",0)),float(request.form.get("lat",0))]}
    col("kyc").insert_one({"user_id":u["_id"],"id_number_encrypted":ids,"selfie_image_id":sid,
      "id_image_id":iid,"signature_image_id":signid,"county":request.form.get("county"),
      "location":loc,"declaration":"I declare that the information I provide is true. If I am paid for a false report, I will refund the reward, and may be required to pay up to 2x as set out in the Terms.",
      "signed_at":now(),"ip":request.remote_addr,"user_agent":request.user_agent.string,
      "terms_version":os.getenv("TERMS_VERSION","1.0"),"status":"Pending","created_at":now()})
    audit("kyc_submitted",u["_id"]); flash("Verification submitted for review.")
    return redirect(url_for("dashboard"))
CATEGORIES=["Dumping","River pollution","Water hyacinth","Illegal logging","Charcoal burning","Unapproved construction","Unsafe structure","Blocked drainage"]
@app.get("/report")
@require("citizen")
def report(): return render_template("report.html",categories=CATEGORIES,brand=brand())
@app.post("/report")
@require("citizen")
@limiter.limit("10 per hour")
def report_submit():
    u=user_doc()
    if u.get("suspended"): abort(403)
    if col("reports").count_documents({"user_id":u["_id"],"created_at":{"$gte":now()-timedelta(days=1)}})>=int(os.getenv("DAILY_REPORT_LIMIT","5")): abort(429,"Daily report limit reached")
    try:
        raw=base64.b64decode(request.form["photo"].split(",")[-1]); data=image_bytes(raw)
        lat=float(request.form["lat"]); lon=float(request.form["lng"]); accuracy=float(request.form["accuracy"])
        captured=datetime.fromisoformat(request.form["captured_at"].replace("Z","+00:00"))
    except Exception: abort(400,"Invalid capture payload")
    report_id="ED-"+uuid.uuid4().hex[:12].upper(); sha=hashlib.sha256(data).hexdigest()
    if col("reports").find_one({"photo_sha256":sha}): abort(409,"Duplicate photo detected")
    point={"type":"Point","coordinates":[lon,lat]}
    nearby=col("reports").find_one({"location":{"$near":{"$geometry":point,"$maxDistance":50}},
      "created_at":{"$gte":now()-timedelta(hours=24)}})
    county=county_for(lon,lat)
    if not county: abort(400,"Location is outside configured counties")
    hits=geo_checks(lon,lat,county); mismatch=bool(u.get("home_county") and u["home_county"]!=county["name"])
    client_skew=abs((now()-captured).total_seconds())>300
    age=(now()-captured).total_seconds()
    gps_ok=accuracy<=MAX_GPS and 0<=age<=30
    spot=bool(gps_ok and not client_skew and not nearby)
    score=fraud_score(u,accuracy,mismatch,lat,lon)
    hold=score>=int(os.getenv("FRAUD_HOLD_THRESHOLD","60"))
    image_id=col("images").insert_one({"bytes":data,"content_type":"image/jpeg","owner_id":str(u["_id"]),
      "kind":"report","encrypted":False,"created_at":now(),"sha256":sha}).inserted_id
    category=request.form.get("category")
    if category not in CATEGORIES: abort(400,"Invalid category")
    report_doc={"report_id":report_id,"user_id":u["_id"],"category":category,"notes":request.form.get("notes","")[:1000],
      "anonymous":request.form.get("anonymous")=="yes","county":county["name"],"ward":request.form.get("ward","")[:100],
      "location":point,"accuracy":accuracy,"captured_at":captured,"server_time":now(),"photo_image_id":image_id,
      "photo_sha256":sha,"spot_verified":spot,"geofence_results":hits,"primary_layer":hits[0]["type"] if hits else "*",
      "fraud_score":score,"home_county_mismatch":mismatch,"repeat_report":bool(nearby),"status":"Pending",
      "priority":"red" if hold or hits else ("orange" if not spot else "green"),"manual_review":not spot or hold,
      "created_at":now(),"approval_board_visible":request.form.get("board"),"permit_number":request.form.get("permit",""),
      "floors_seen":request.form.get("floors"),"cracks":request.form.get("cracks")}
    rid=col("reports").insert_one(report_doc).inserted_id
    route_report(report_doc|{"_id":rid})
    audit("report_created",rid,{"report_id":report_id})
    return redirect(url_for("dashboard"))
@app.get("/img/<image_id>")
def public_image(image_id):
    im=col("images").find_one({"_id":oid(image_id),"kind":"report","encrypted":False})
    if not im: abort(404)
    return send_file(io.BytesIO(im["bytes"]),mimetype=im["content_type"])
@app.get("/admin/kyc-image/<image_id>")
@require("admin")
def admin_kyc_image(image_id):
    im=col("images").find_one({"_id":oid(image_id),"encrypted":True})
    if not im: abort(404)
    audit("kyc_image_view",image_id)
    try: data=decrypt(im["bytes"])
    except InvalidToken: abort(500)
    return send_file(io.BytesIO(data),mimetype="image/jpeg")
@app.get("/admin/login")
def admin_login(): return render_template("admin_login.html",brand=brand())
@app.post("/admin/login")
@limiter.limit("5 per hour")
def admin_login_post():
    email=request.form.get("email","").lower().strip()
    password=request.form.get("password","")
    stored=os.getenv("ADMIN_PASSWORD_HASH","")
    if not stored or email!=os.getenv("ADMIN_EMAIL","").lower() or not check_password_hash(stored,password):
        abort(401,"Invalid administrator credentials")
    u=col("users").find_one({"email":email,"role":"admin"})
    if not u:
        # Secure first-login bootstrap: create the administrator only after the
        # submitted credentials have matched the deployment's ADMIN_PASSWORD_HASH.
        # This avoids requiring a shell/seed.py execution on Vercel.
        try:
            result=col("users").insert_one({
                "email":email,
                "password_hash":stored,
                "role":"admin",
                "tier":2,
                "created_at":now(),
                "bootstrap_admin":True
            })
            u=col("users").find_one({"_id":result.inserted_id})
        except DuplicateKeyError:
            u=col("users").find_one({"email":email,"role":"admin"})
        if not u:
            app.logger.error("Admin bootstrap failed for configured ADMIN_EMAIL")
            abort(503,"Administrator account could not be initialized. Check MongoDB permissions and indexes.")
    session.clear(); session.update(uid=str(u["_id"]),role="admin")
    audit("admin_login",u["_id"])
    return redirect(url_for("admin"))

@app.get("/admin")
@require("admin")
def admin():
    counts={"reports":col("reports").count_documents({}),"pending":col("reports").count_documents({"status":"Pending"}),
      "paid":col("payouts").count_documents({"status":"Sent"}),"users":col("users").count_documents({}),
      "hotspots":col("hotspots").count_documents({})}
    return render_template("admin.html",counts=counts,kycs=list(col("kyc").find({"status":"Pending"}).limit(100)),
      reports=list(col("reports").find().sort("created_at",-1).limit(100)),
      stk_transactions=list(col("stk_transactions").find().sort("created_at",-1).limit(50)),brand=brand())
@app.post("/admin/kyc/<kid>/decision")
@require("admin")
def kyc_decision(kid):
    decision=request.form.get("decision"); reason=request.form.get("reason","")[:500]
    if decision not in ("Approve","Reject"): abort(400)
    k=col("kyc").find_one({"_id":oid(kid)})
    if not k: abort(404)
    col("kyc").update_one({"_id":k["_id"]},{"$set":{"status":decision,"decision_reason":reason,"decided_at":now(),"decided_by":session["uid"]}})
    if decision=="Approve": col("users").update_one({"_id":k["user_id"]},{"$set":{"tier":1,"level":"Patroller","home_county":k["county"]}})
    audit("kyc_"+decision.lower(),kid,{"reason":reason})
    return redirect(url_for("admin"))
def daraja_base():
    # Production is explicit; missing/invalid config falls back safely to sandbox.
    return "https://api.safaricom.co.ke" if os.getenv("DARAJA_ENV","sandbox").lower()=="production" else "https://sandbox.safaricom.co.ke"
def daraja_access_token():
    key=os.getenv("DARAJA_CONSUMER_KEY"); secret=os.getenv("DARAJA_CONSUMER_SECRET")
    if not key or not secret: raise RuntimeError("Daraja consumer credentials are not configured")
    r=requests.get(daraja_base()+"/oauth/v1/generate?grant_type=client_credentials",
      auth=(key,secret),timeout=15)
    r.raise_for_status()
    token=r.json().get("access_token")
    if not token: raise RuntimeError("Daraja did not return an access token")
    return token
def daraja_stk_push(phone, amount, reference, callback_url):
    shortcode=os.getenv("DARAJA_BUSINESS_SHORTCODE","").strip()
    party_b=os.getenv("DARAJA_PARTY_B","").strip()
    passkey=os.getenv("DARAJA_PASSKEY","").strip()
    if not shortcode or not party_b or not passkey:
        raise RuntimeError("Configure DARAJA_BUSINESS_SHORTCODE, DARAJA_PARTY_B and DARAJA_PASSKEY")
    timestamp=now().astimezone(timezone(timedelta(hours=3))).strftime("%Y%m%d%H%M%S")
    password=base64.b64encode((shortcode+passkey+timestamp).encode()).decode()
    payload={"BusinessShortCode":shortcode,"Password":password,"Timestamp":timestamp,
      "TransactionType":"CustomerBuyGoodsOnline","Amount":int(amount),"PartyA":phone,
      "PartyB":party_b,"PhoneNumber":phone,"CallBackURL":callback_url,
      "AccountReference":reference[:12],"TransactionDesc":"EcoDoria payment"}
    r=requests.post(daraja_base()+"/mpesa/stkpush/v1/processrequest",
      headers={"Authorization":"Bearer "+daraja_access_token(),"Content-Type":"application/json"},
      json=payload,timeout=20)
    r.raise_for_status()
    return r.json()

@app.post("/admin/daraja/stk-prompt")
@require("admin")
@limiter.limit("20 per hour")
def admin_stk_prompt():
    # This is C2B collection into EcoDoria's Buy Goods Till, never a citizen payout.
    phone=re.sub(r"\D","",request.form.get("phone",""))
    if phone.startswith("0"): phone="254"+phone[1:]
    if phone.startswith("+"): phone=phone[1:]
    amount=int(request.form.get("amount","0"))
    if not re.fullmatch(r"254[17][0-9]{8}",phone) or amount<1 or amount>250000: abort(400,"Enter a valid Kenyan Safaricom number and amount (KES 1–250,000)")
    txid=col("stk_transactions").insert_one({"phone":phone,"amount_kes":amount,"status":"Initiating",
      "direction":"C2B_COLLECTION","transaction_type":"CustomerBuyGoodsOnline","created_at":now(),
      "created_by":session["uid"],"reference":"ED"+uuid.uuid4().hex[:10].upper(),
      "memo":request.form.get("memo","")[:200]}).inserted_id
    callback_token=secrets.token_urlsafe(32)
    callback_url=request.url_root.rstrip("/")+"/api/daraja/callback/"+callback_token
    try:
        result=daraja_stk_push(phone,amount,col("stk_transactions").find_one({"_id":txid})["reference"],callback_url)
        if result.get("ResponseCode")!="0":
            col("stk_transactions").update_one({"_id":txid},{"$set":{"status":"Failed","daraja_response":result}})
            message=str(result.get("ResponseDescription") or result.get("errorMessage") or "Daraja did not accept the request")
            flash("STK request failed: "+message)
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify(ok=False,status="Failed",message=message), 400
        else:
            col("stk_transactions").update_one({"_id":txid},{"$set":{"status":"Prompt sent","merchant_request_id":result.get("MerchantRequestID"),
              "checkout_request_id":result.get("CheckoutRequestID"),"callback_token_hash":hashlib.sha256(callback_token.encode()).hexdigest(),
              "daraja_response":result}})
            audit("daraja_stk_prompt",txid,{"amount":amount,"phone_last4":phone[-4:]})
            flash("STK prompt sent. Awaiting customer authorization and Safaricom confirmation.")
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify(ok=True,txid=str(txid),status="Prompt sent",
                    message="Prompt sent. Check the customer's phone and enter the M-Pesa PIN to complete payment.")
    except Exception as e:
        app.logger.exception("Daraja STK request failed")
        safe_error="Could not send the M-Pesa prompt. Please verify Daraja credentials, shortcode/Till configuration, callback URL and network, then try again."
        col("stk_transactions").update_one({"_id":txid},{"$set":{"status":"Failed","error":str(e)[:300],"result_description":safe_error}})
        flash(safe_error)
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify(ok=False,status="Failed",message=safe_error), 502
    return redirect(url_for("admin"))

@app.get("/admin/daraja/status/<txid>")
@require("admin")
def admin_daraja_status(txid):
    try:
        tx=col("stk_transactions").find_one({"_id":oid(txid)})
    except Exception:
        tx=None
    if not tx: return jsonify(ok=False,message="Payment request not found"),404
    status=tx.get("status","Initiating")
    messages={
      "Paid":"Payment confirmed successfully by Safaricom.",
      "Cancelled":"The customer cancelled the M-Pesa request. No payment was received.",
      "Failed":tx.get("result_description") or tx.get("error") or "The payment could not be completed. No payment was confirmed.",
      "Prompt sent":"STK prompt sent. Waiting for the customer to authorize payment.",
      "Initiating":"Sending payment request to Safaricom."
    }
    return jsonify(ok=True,status=status,message=messages.get(status,"Payment status is being checked."),
      receipt=tx.get("mpesa_receipt"),amount=tx.get("paid_amount") or tx.get("amount_kes"),
      reference=tx.get("reference"))

@app.get("/admin/daraja/receipt/<txid>")
@require("admin")
def daraja_receipt(txid):
    tx=col("stk_transactions").find_one({"_id":oid(txid),"status":"Paid"})
    if not tx: abort(404,"A receipt is available only after a successful Safaricom callback")
    audit("daraja_receipt_view",txid)
    return render_template("daraja_receipt.html",t=tx,receipt_no="ED-MPESA-"+str(tx.get("mpesa_receipt") or tx["_id"])[-12:].upper(),brand=brand())

@app.post("/api/daraja/callback/<token>")
@csrf.exempt
@limiter.limit("120 per minute")
def daraja_callback(token):
    token_hash=hashlib.sha256(token.encode()).hexdigest()
    tx=col("stk_transactions").find_one({"callback_token_hash":token_hash})
    if not tx: abort(404)
    body=request.get_json(silent=True) or {}
    callback=body.get("Body",{}).get("stkCallback",{})
    if callback.get("CheckoutRequestID")!=tx.get("checkout_request_id"): abort(400)
    # Safaricom callbacks are not cryptographically signed; the per-request unguessable URL
    # plus matching CheckoutRequestID and idempotent status transition reduce spoof/replay risk.
    if tx.get("status") in ("Paid","Cancelled","Failed"): return jsonify(ResultCode=0,ResultDesc="Already processed")
    code=callback.get("ResultCode")
    update={"daraja_callback":body,"callback_received_at":now()}
    if str(code)=="0":
        meta={x.get("Name"):x.get("Value") for x in callback.get("CallbackMetadata",{}).get("Item",[])}
        update.update({"status":"Paid","mpesa_receipt":meta.get("MpesaReceiptNumber"),
          "paid_amount":meta.get("Amount"),"paid_phone":str(meta.get("PhoneNumber","")),
          "transaction_date":meta.get("TransactionDate")})
    else:
        update.update({"status":"Cancelled" if str(code)=="1032" else "Failed",
          "result_code":code,"result_description":callback.get("ResultDesc","")})
    col("stk_transactions").update_one({"_id":tx["_id"],"status":{"$nin":["Paid","Cancelled","Failed"]}},{"$set":update})
    audit("daraja_callback",tx["_id"],{"result_code":code})
    return jsonify(ResultCode=0,ResultDesc="Accepted")

@app.post("/admin/wallet/credit")
@require("admin")
def wallet_credit():
    phone=request.form.get("phone",""); amount=int(request.form.get("amount","0"))
    if amount<=0 or amount>1000000: abort(400)
    u=col("users").find_one({"phone":phone})
    if not u: abort(404,"User not found")
    pid=col("payouts").insert_one({"user_id":u["_id"],"type":"admin_credit","amount_kes":amount,
      "status":"Available","memo":request.form.get("memo","")[:300],"created_at":now(),"created_by":session["uid"]}).inserted_id
    col("users").update_one({"_id":u["_id"]},{"$inc":{"wallet_balance":amount}})
    audit("wallet_credit",pid,{"amount":amount,"phone":phone})
    flash("Wallet credited. No payment was sent.")
    return redirect(url_for("admin"))
@app.post("/wallet/destination")
@require("citizen")
def wallet_destination():
    phone=request.form.get("mpesa_phone","")
    if not re.fullmatch(r"\\+?254[17][0-9]{8}",phone): abort(400,"Use +2547XXXXXXXX or +2541XXXXXXXX")
    col("users").update_one({"_id":oid(session["uid"])},{"$set":{"payout_destination":encrypt(phone),"destination_updated_at":now()}})
    audit("payout_destination_updated"); flash("Withdrawal destination updated.")
    return redirect(url_for("dashboard"))
@app.post("/wallet/withdraw")
@require("citizen")
def withdraw_request():
    u=user_doc(); amount=int(request.form.get("amount","0"))
    if amount<=0 or amount>u.get("wallet_balance",0): abort(400,"Invalid amount")
    if not u.get("payout_destination"): abort(400,"Update your M-Pesa details first")
    # Withdrawal requests are queued for the next 1st/15th. No B2C call exists.
    d=now().date()
    if d.day<15: due=d.replace(day=15)
    else:
        first=(d.replace(day=1)+timedelta(days=32)).replace(day=1)
        due=first
    col("payouts").insert_one({"user_id":u["_id"],"type":"withdrawal","amount_kes":amount,
      "status":"Requested","scheduled_date":due.isoformat(),"created_at":now(),"destination_snapshot":u["payout_destination"]})
    col("users").update_one({"_id":u["_id"]},{"$inc":{"wallet_balance":-amount,"wallet_reserved":amount}})
    audit("withdrawal_requested",u["_id"],{"amount":amount,"due":due.isoformat()})
    flash("Withdrawal queued. Payment is not yet sent.")
    return redirect(url_for("dashboard"))
@app.post("/admin/payout/<pid>/mark-sent")
@require("admin")
def mark_payout_sent(pid):
    ref=request.form.get("transaction_ref","").strip()
    if not ref: abort(400,"M-Pesa transaction reference required")
    p=col("payouts").find_one({"_id":oid(pid),"type":"withdrawal","status":"Requested"})
    if not p: abort(404)
    col("payouts").update_one({"_id":p["_id"]},{"$set":{"status":"Sent","transaction_ref":ref,"sent_at":now(),"sent_by":session["uid"]}})
    col("users").update_one({"_id":p["user_id"]},{"$inc":{"wallet_reserved":-p["amount_kes"]}})
    audit("manual_payout_recorded",pid,{"transaction_ref":ref})
    return jsonify(ok=True,receipt_url=url_for("receipt",pid=pid))
@app.get("/receipt/<pid>")
@require("admin","citizen")
def receipt(pid):
    p=col("payouts").find_one({"_id":oid(pid)})
    if not p: abort(404)
    if session["role"]!="admin" and str(p["user_id"])!=session["uid"]: abort(403)
    return render_template("receipt.html",p=p,receipt_no="ED-RCPT-"+str(p["_id"])[-8:].upper(),brand=brand())
@app.get("/o/<token>")
@limiter.limit("20 per hour")
def officer_magic(token):
    th=hashlib.sha256(token.encode()).hexdigest()
    link=col("officer_links").find_one({"token_hash":th,"expires_at":{"$gt":now()},"used":False})
    if not link: abort(403,"Expired or invalid officer link")
    off=col("officers").find_one({"_id":link["officer_id"]})
    session.clear(); session.update(uid=str(off["_id"]),role="officer",officer_id=str(off["_id"]))
    col("officer_links").update_one({"_id":link["_id"]},{"$set":{"used":True}})
    return redirect(url_for("officer_dashboard"))
def officer_scope(officer):
    return {"agency_id":officer["agency_id"],"county":{"$in":officer.get("counties",[])}}
@app.get("/officer")
@require("officer")
def officer_dashboard():
    off=col("officers").find_one({"_id":oid(session["uid"])})
    if not off: abort(403)
    reports=list(col("reports").find(officer_scope(off)).sort("created_at",-1).limit(200))
    audit("officer_dashboard_view",off["_id"])
    return render_template("officer.html",reports=reports,brand=brand())
@app.post("/officer/report/<rid>/decision")
@require("officer")
def officer_decision(rid):
    off=col("officers").find_one({"_id":oid(session["uid"])})
    r=col("reports").find_one({"_id":oid(rid),**officer_scope(off)})
    if not r: abort(404)
    action=request.form.get("decision")
    if action not in ("Verified","Rejected","Non-compliant"): abort(400)
    status="Verified" if action in ("Verified","Non-compliant") else "Rejected"
    col("reports").update_one({"_id":r["_id"]},{"$set":{"status":status,"officer_decision":action,
      "decision_reason":request.form.get("reason","")[:500],"verified_by":off["_id"],"verified_at":now()}})
    if status=="Verified":
        u=col("users").find_one({"_id":r["user_id"]})
        if u and u.get("tier",0)>=1 and not r.get("reward_queued"):
            cap=int(os.getenv("DAILY_PAYOUT_CAP_KES","500"))
            paid=col("payouts").aggregate([{"$match":{"user_id":u["_id"],"created_at":{"$gte":now()-timedelta(days=1)}}},{"$group":{"_id":None,"s":{"$sum":"$amount_kes"}}}])
            spent=next(paid,{}).get("s",0)
            amount=min(REWARD,max(0,cap-spent))
            if amount:
                col("payouts").insert_one({"user_id":u["_id"],"type":"report_reward","amount_kes":amount,
                  "status":"Available","report_id":r["_id"],"created_at":now()})
                col("users").update_one({"_id":u["_id"]},{"$inc":{"wallet_balance":amount,"confirmed_reports":1,"reputation":5}})
        if u and u.get("confirmed_reports",0)+1>=5: col("users").update_one({"_id":u["_id"]},{"$set":{"tier":2,"level":"Senior Patroller"}})
    audit("officer_"+action.lower(),rid)
    return redirect(url_for("officer_dashboard"))
@app.post("/officer/report/<rid>/reassign")
@require("officer")
def officer_reassign(rid):
    off=col("officers").find_one({"_id":oid(session["uid"])})
    r=col("reports").find_one({"_id":oid(rid),**officer_scope(off)})
    if not r: abort(404)
    agency=col("agencies").find_one({"name":request.form.get("agency")})
    if not agency: abort(400)
    col("reports").update_one({"_id":r["_id"]},{"$set":{"agency_id":agency["_id"],"agency_name":agency["name"]}})
    audit("report_reassigned",rid,{"agency":agency["name"]})
    return redirect(url_for("officer_dashboard"))
# LEGAL TODO: the refund clause requires Kenyan legal review and ODPC registration before real launch.
@app.get("/terms")
def terms(): return render_template("legal.html",privacy=False,brand=brand())
@app.get("/privacy")
def privacy(): return render_template("legal.html",privacy=True,brand=brand())
def _authorize_vercel_cron():
    """Authenticate native Vercel Cron requests using CRON_SECRET.

    Vercel sends: Authorization: Bearer <CRON_SECRET>.
    X-Cron-Secret remains accepted for manually configured external schedulers.
    """
    secret=os.getenv("CRON_SECRET","").strip()
    if not secret:
        app.logger.error("CRON_SECRET is not configured; rejecting cron request")
        abort(503, description="Cron authentication is not configured.")
    authorization=request.headers.get("Authorization","")
    bearer=authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
    supplied=bearer or request.headers.get("X-Cron-Secret","")
    if not supplied or not __import__("hmac").compare_digest(supplied,secret):
        abort(403)


@app.route("/api/cron/escalate", methods=["GET","POST"])
@csrf.exempt
def cron_escalate():
    _authorize_vercel_cron()
    stale=list(col("reports").find({"status":"Pending","created_at":{"$lt":now()-timedelta(hours=48)},"escalated":{"$ne":True}}))
    for r in stale:
        send_email(os.getenv("ADMIN_EMAIL",""),"EcoDoria escalation",f"<p>Report {r['report_id']} remains pending in {r['county']}.</p>")
        col("reports").update_one({"_id":r["_id"]},{"$set":{"escalated":True,"escalated_at":now()}})
    return jsonify(escalated=len(stale))
@app.route("/api/cron/hotspots", methods=["GET","POST"])
@csrf.exempt
def cron_hotspots():
    _authorize_vercel_cron()
    col("hotspots").delete_many({})
    pipeline=[{"$match":{"status":{"$in":["Pending","Verified"]}}},{"$group":{"_id":{"county":"$county","lat":{"$floor":{"$arrayElemAt":["$location.coordinates",1]}},"lng":{"$floor":{"$arrayElemAt":["$location.coordinates",0]}}},"n":{"$sum":1}}},{"$match":{"n":{"$gte":3}}}]
    n=0
    for h in col("reports").aggregate(pipeline):
        col("hotspots").insert_one({"county":h["_id"]["county"],"count":h["n"],"location":{"type":"Point","coordinates":[h["_id"]["lng"]+.005,h["_id"]["lat"]+.005]},"created_at":now()}); n+=1
    return jsonify(hotspots=n)
@app.route("/api/cron/kyc-retention", methods=["GET","POST"])
@csrf.exempt
def cron_kyc_retention():
    _authorize_vercel_cron()
    cutoff=now()-timedelta(days=int(os.getenv("KYC_RETENTION_DAYS","30")))
    ks=list(col("kyc").find({"status":{"$in":["Approve","Reject"]},"decided_at":{"$lt":cutoff},"images_deleted":{"$ne":True}}))
    for k in ks:
        for field in ("selfie_image_id","id_image_id","signature_image_id"):
            col("images").delete_one({"_id":k[field]})
        col("kyc").update_one({"_id":k["_id"]},{"$set":{"images_deleted":True,"encrypted_id_reference":k.get("id_number_encrypted")}})
    return jsonify(deleted=len(ks))
@app.route("/api/cron/weekly-summary", methods=["GET","POST"])
@csrf.exempt
def cron_summary():
    _authorize_vercel_cron()
    since=now()-timedelta(days=7); reports=col("reports").count_documents({"created_at":{"$gte":since}})
    paid=list(col("payouts").aggregate([{"$match":{"status":"Sent","created_at":{"$gte":since}}},{"$group":{"_id":None,"sum":{"$sum":"$amount_kes"}}}]))
    send_email(os.getenv("ADMIN_EMAIL",""),"EcoDoria weekly summary",f"<p>Reports: {reports}; rewards paid: {paid[0]['sum'] if paid else 0} KES.</p>")
    return jsonify(reports=reports)
@app.errorhandler(500)
def server_error(e):
    app.logger.exception("Server error: %s",e)
    return "EcoDoria configuration or server error. Check deployment logs.",500
if db is not None:
    try: create_indexes()
    except Exception: app.logger.exception("MongoDB index setup failed")
if __name__=="__main__": app.run(debug=os.getenv("FLASK_DEBUG","false").lower()=="true")
