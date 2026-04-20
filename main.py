from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
import numpy as np
import joblib
import os
from utility import main as extract_features

app = FastAPI(title="ReNoteAI URL Shield")
model = None

@app.on_event("startup")
async def load_model():
    global model
    if not os.path.exists("model.pkl"):
        raise RuntimeError("model.pkl not found!")
    model = joblib.load("model.pkl")
    print(f"Model loaded! Expected features: {model.n_features_in_}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")

class URLData(BaseModel):
    url: str

@app.get("/")
async def root():
    return FileResponse("static/index.html", headers={"Cache-Control": "no-cache, no-store, must-revalidate"})

SAFE_DOMAINS = {
    'google.com', 'youtube.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'facebook.com', 'twitter.com', 'instagram.com',
    'linkedin.com', 'github.com', 'wikipedia.org', 'netflix.com',
    'reddit.com', 'yahoo.com', 'bing.com', 'stackoverflow.com',
    'whatsapp.com', 'zoom.us', 'dropbox.com', 'spotify.com',
    'onrender.com', 'url-shield-psms.onrender.com'
}

@app.post("/classify-url/")
async def classify_url(url_data: URLData):
    # Check against known safe domains
    from urllib.parse import urlparse
    try:
        hostname = urlparse(url_data.url).hostname or ''
        hostname = hostname.replace('www.', '')
        print(f"Hostname: {hostname}")
        print(f"In whitelist: {hostname in SAFE_DOMAINS}")
        if hostname in SAFE_DOMAINS:
            return {"url": url_data.url, "classification": "SAFE"}
    except Exception as e:
        print(f"Whitelist error: {e}")

    features = extract_features(url_data.url)
    features = np.array(features).reshape((1, -1))
    print(f"Features extracted: {len(features[0])}")
    prediction = model.predict(features)
    categories = {0: "SAFE", 1: "MALICIOUS"}
    result = categories.get(int(prediction[0]), "Unknown")
    return {"url": url_data.url, "classification": result}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)