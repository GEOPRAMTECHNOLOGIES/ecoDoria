"""Run: python seed.py. Creates first admin, demo county and default agencies/routing."""
import os
from datetime import datetime,timezone
from dotenv import load_dotenv
from pymongo import MongoClient
from werkzeug.security import generate_password_hash
load_dotenv()
db=MongoClient(os.environ["MONGODB_URI"])[os.getenv("MONGODB_DB","ecodoria")]
email=(os.getenv("ADMIN_EMAIL") or "").strip().lower()
pw=os.getenv("ADMIN_PASSWORD")
password_hash=os.getenv("ADMIN_PASSWORD_HASH")
if not email: raise SystemExit("Set ADMIN_EMAIL before seeding")
if not password_hash and pw:
    password_hash=generate_password_hash(pw)
if not password_hash:
    raise SystemExit("Set ADMIN_PASSWORD_HASH, or set ADMIN_PASSWORD to generate the hash.")
db.users.update_one(
    {"email":email},
    {"$setOnInsert":{"email":email,"password_hash":password_hash,"role":"admin",
      "tier":2,"created_at":datetime.now(timezone.utc),"bootstrap_admin":True}},
    upsert=True
)
county={"name":"Meru","active":True,"geometry":{"type":"Polygon","coordinates":[[[37.2,-0.3],[38.3,-0.3],[38.3,0.4],[37.2,0.4],[37.2,-0.3]]]},"created_at":datetime.now(timezone.utc)}
db.counties.update_one({"name":"Meru"},{"$setOnInsert":county},upsert=True)
names=["NEMA","County Planning","NCA","WRA","KFS"]
for n in names: db.agencies.update_one({"name":n},{"$setOnInsert":{"name":n,"active":True}},upsert=True)
agency={x["name"]:x["_id"] for x in db.agencies.find({"name":{"$in":names}})}
for category,name in [("Dumping","NEMA"),("River pollution","WRA"),("Water hyacinth","WRA"),("Illegal logging","KFS"),("Charcoal burning","KFS"),("Unapproved construction","County Planning"),("Unsafe structure","NCA"),("Blocked drainage","County Planning")]:
    db.routing_rules.update_one({"category":category,"county":"Meru","layer_type":"*"},{"$set":{"agency_id":agency[name]}},upsert=True)
print("Seed complete. The bootstrap administrator is ready.")
