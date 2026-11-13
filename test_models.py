import os
import time
from dotenv import load_dotenv
from google import genai

load_dotenv()
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

names = [
    m.name.replace("models/", "")
    for m in client.models.list()
    if "flash" in m.name and "image" not in m.name and "tts" not in m.name
]

for name in names[:8]:
    start = time.time()
    try:
        client.models.generate_content(model=name, contents="Reply with OK")
        print(f"WORKS  {name}  {round(time.time() - start, 1)}s")
    except Exception as e:
        print(f"FAILS  {name}  {str(e)[:70]}")