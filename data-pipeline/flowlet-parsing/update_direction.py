import json
import os
from pymongo import MongoClient
from dotenv import load_dotenv
from bson.objectid import ObjectId
from collections import Counter

# 1. Setup Connection
load_dotenv()
client = MongoClient(os.getenv("MONGODB_URI"))
db = client['networks_project']
captures_col = db['captures']

# --- HARD-CODED TARGETS ---
TARGET_IDS = [
    "3_14_26_non_llm_bot_0.1", 
    "3-19-26-non-llm-longer_0.1",
    "3-19-26-non-llm-10-min_0.1",
    "non-llm-03272026-1130_0.1",
]

def _get_captures_collection():
    load_dotenv()
    mongo_uri = os.getenv("MONGODB_URI")
    if not mongo_uri:
        raise RuntimeError("MONGODB_URI is not set. Refusing to run.")

    client = MongoClient(mongo_uri)
    db = client["networks_project"]
    return db["captures"]


def _pick_host_ip(flowlets):
    """
    Heuristic: pick the most common src/dst IP across the capture.
    We only use this to set a direction flag for non-LLM flowlets.
    """
    ip_counts = Counter()
    for f in flowlets:
        if not isinstance(f, dict):
            continue
        fk = f.get("flow_key", {}) or {}
        src, dst = fk.get("src_ip"), fk.get("dst_ip")
        if src:
            ip_counts.update([src])
        if dst:
            ip_counts.update([dst])

    if not ip_counts:
        return None

    host_ip, _count = ip_counts.most_common(1)[0]
    return host_ip


def update_direction_flags(target_ids=None):
    """
    Adds `outgoing` (bool) to non-LLM flowlets only.

    Guardrails:
    - Does not connect to Mongo at import time.
    - Does not modify LLM flowlets.
    - Does not overwrite existing `outgoing` values.
    - Does not add any additional fields beyond `outgoing`.
    - Does not write to Mongo if no flowlets were updated.
    """
    captures_col = _get_captures_collection()

    target_ids = TARGET_IDS if target_ids is None else target_ids
    for target in target_ids:
        query_id = ObjectId(target) if ObjectId.is_valid(target) else target
        cap = captures_col.find_one({"_id": query_id})

        if not cap:
            print(f"❌ Capture {target} not found.")
            continue

        flowlets = cap.get('flowlets')
        if not flowlets:
            print(f"⚠️ No flowlets found in capture {target}.")
            continue
        
        if not isinstance(flowlets, list):
            print(f"⚠️ Capture {target} has non-list flowlets; skipping.")
            continue

        host_ip = _pick_host_ip(flowlets)
        if not host_ip:
            print(f"⚠️ Could not infer host IP for capture {target}; skipping.")
            continue

        updated = 0
        for f in flowlets:
            if not isinstance(f, dict):
                continue

            # Only non-LLM flowlets
            if f.get("llm_name"):
                continue

            # Only add the flag; never overwrite it
            if "outgoing" in f:
                continue

            fk = f.get("flow_key", {}) or {}
            src, dst = fk.get("src_ip"), fk.get("dst_ip")

            # Only set direction when host IP participates in the flowlet
            if src == host_ip:
                f["outgoing"] = True
                updated += 1
            elif dst == host_ip:
                f["outgoing"] = False
                updated += 1

        print(f"📊 Summary for {target}:")
        print(f"   - Host IP heuristic: {host_ip}")
        print(f"   - Non-LLM flowlets updated (outgoing added): {updated}")

        if updated == 0:
            print("   ↩️  No changes to write.")
            print("-" * 40)
            continue

        captures_col.update_one({"_id": query_id}, {"$set": {"flowlets": flowlets}})
        print(f"   ✅ Wrote updated flowlets array (added `outgoing` to {updated}).")
        print("-" * 40)

if __name__ == "__main__":
    update_direction_flags()