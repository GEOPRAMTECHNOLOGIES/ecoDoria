"""Run: python seed.py. Creates first admin, demo county and default agencies/routing."""
import os
from datetime import datetime,timezone
from dotenv import load_dotenv
from pymongo import MongoClient
from werkzeug.security import generate_password_hash
load_dotenv()
db=MongoClient(os.environ["MONGODB_URI"])[os.getenv("MONGODB_DB","ecodoria")]
email=os.getenv("ADMIN_EMAIL"); pw=os.getenv("ADMIN_PASSWORD")
if not email or not pw: raise SystemExit("Set ADMIN_EMAIL and ADMIN_PASSWORD before seeding")
db.users.update_one({"email":email},{"$setOnInsert":{"email":email,"phone":"+254700000000","password_hash":generate_password_hash(pw),"role":"admin","tier":2,"created_at":datetime.now(timezone.utc)}},upsert=True)
county={"name":"Meru","active":True,"geometry":{"type":"Polygon","coordinates":[[[37.2,-0.3],[38.3,-0.3],[38.3,0.4],[37.2,0.4],[37.2,-0.3]]]},"created_at":datetime.now(timezone.utc)}
db.counties.update_one({"name":"Meru"},{"$setOnInsert":county},upsert=True)
names=["NEMA","County Planning","NCA","WRA","KFS"]
for n in names: db.agencies.update_one({"name":n},{"$setOnInsert":{"name":n,"active":True}},upsert=True)
agency={x["name"]:x["_id"] for x in db.agencies.find({"name":{"$in":names}})}
for category,name in [("Dumping","NEMA"),("River pollution","WRA"),("Water hyacinth","WRA"),("Illegal logging","KFS"),("Charcoal burning","KFS"),("Unapproved construction","County Planning"),("Unsafe structure","NCA"),("Blocked drainage","County Planning")]:
    db.routing_rules.update_one({"category":category,"county":"Meru","layer_type":"*"},{"$set":{"agency_id":agency[name]}},upsert=True)
print("Seed complete. Change the seeded admin phone before production.")
