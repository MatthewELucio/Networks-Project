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

def update_direction_and_labels():
    for target in TARGET_IDS:
        query_id = ObjectId(target) if ObjectId.is_valid(target) else target
        cap = captures_col.find_one({"_id": query_id})

        if not cap:
            print(f"❌ Capture {target} not found.")
            continue

        flowlets = cap.get('flowlets')
        if not flowlets:
            print(f"⚠️ No flowlets found in capture {target}.")
            continue
        
        # --- STEP 1: Find the Host IP (intersection of all flowlets) ---
        ip_counts = Counter()
        first = flowlets[0]
        # Access nested flow_key
        f_key = first.get('flow_key', {})
        ip_counts.update([f_key.get('src_ip'), f_key.get('dst_ip')])
        
        for f in flowlets[1:]:
            fk = f.get('flow_key', {})
            src, dst = fk.get('src_ip'), fk.get('dst_ip')
            ip_counts.update([src, dst])
            
        host_ip, count = ip_counts.most_common(1)[0]
        print(host_ip, count, len(flowlets))

        # --- STEP 2: Map LLM Names and Encode Direction ---
        
        non_llm_updated_count = 0

        for f in flowlets:
            fk = f.get('flow_key', {})
            src, dst = fk.get('src_ip'), fk.get('dst_ip')
            
            llm_name = f.get('llm_name')

            # ONLY update direction if it is NOT an LLM flow
            if not llm_name and (src == host_ip or dst == host_ip):
                if src == host_ip:
                    f['outgoing'] = False
                    f['direction_encoded'] = -1
                else:
                    f['outgoing'] = True
                    f['direction_encoded'] = 1
                
                f['updated_direction_by_script'] = True
                non_llm_updated_count += 1

        print(f"📊 Summary for {target}:")
        print(f"   - Non-LLM flows updated/marked: {non_llm_updated_count}")

        # --- STEP 3: Push back to MongoDB ---
        captures_col.update_one(
            {"_id": query_id},
            {"$set": {"flowlets": flowlets}}
        )
        print(f"   ✅ Successfully updated {len(flowlets)} flowlets ({non_llm_updated_count} LLM flows matched).")
        print("-" * 40)

if __name__ == "__main__":
    update_direction_and_labels()