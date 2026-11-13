import json
import os
import time

from analyzer import analyze_message
from examples import EXAMPLES
from masking import mask_sensitive, text_key

PATH = "examples_cache.json"
cache = json.load(open(PATH, encoding="utf-8")) if os.path.exists(PATH) else {}

for name, text in EXAMPLES.items():
    key = text_key(text)
    if key in cache:
        print(f"skip (already saved): {name}")
        continue
    masked, _ = mask_sensitive(text.strip())
    for attempt in range(3):
        out = analyze_message(masked)
        if "error" not in out:
            break
        print(f"   error: {out['error'][:120]}")
        time.sleep(30 * (attempt + 1))
    else:
        print("Stopped. Progress saved. Run again later.")
        break
    cache[key] = out
    with open(PATH, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=1)
    print(f"saved: {name} -> {out['label']}")
    time.sleep(15)