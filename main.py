from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
import numpy as np
import joblib
from utility import main

model = joblib.load("model.pkl")
app = FastAPI(title="ReNoteAI URL Shield")

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
@app.post("/classify-url/")
async def classify_url(url_data: URLData):
    features = main(url_data.url)
    features = np.array(features).reshape((1, -1))
    prediction = model.predict(features)
    categories = {0: "SAFE", 1: "MALICIOUS"}
    result = categories.get(int(prediction[0]), "Unknown")
    return {"url": url_data.url, "classification": result}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)