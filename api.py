from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from featureExtractor import PredictURL
import validators
import os
from dotenv import load_dotenv
import requests
import google.generativeai as genai

# Initialize FastAPI app
app = FastAPI()

# Load environment variables
load_dotenv()

# Fetch API key from .env
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "dummy-key")
if GOOGLE_API_KEY == "dummy-key":
    print("WARNING: Using dummy API key. Set GOOGLE_API_KEY in .env or environment.")

# Configure Gemini API
genai.configure(api_key=GOOGLE_API_KEY)
model = genai.GenerativeModel("gemini-pro")

# Load your URL classification model
classification = PredictURL()

# Function to run Gemini LLM analysis
def run_gpt_analysis(subject, body):
    prompt = f"""
    Analyze the following email for phishing indicators.

    Subject: {subject}
    Body: {body}

    Respond with an explanation of whether this might be phishing and why.
    """
    response = model.generate_content(prompt)
    return response.text

# Root test route
@app.get("/")
def read_root():
    return {"message": "Phishing Detection API is running!"}

@app.get("/test-api-key")
def test_api_key():
    return {"GOOGLE_API_KEY": GOOGLE_API_KEY}

# Enable CORS
origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Define the input schema
class EmailData(BaseModel):
    subject: str
    body: str
    urls: list[str]
    attachment_filenames: list[str]

# Email analysis endpoint
@app.post("/api/analyze")
async def analyze_email(data: EmailData):
    response = {
        "phishing_urls": [],
        "suspicious_attachments": [],
        "llm_analysis": ""
    }

    # ML phishing detection on URLs
    for url in data.urls:
        if validators.url(url):
            result = classification.predict(url)
            if result != "Given website is a legitimate site":
                response["phishing_urls"].append({"url": url, "verdict": result})

    # Detect suspicious file extensions
    sus_extensions = ['.exe', '.bat', '.cmd', '.scr', '.js', '.vbs', '.jar']
    for fname in data.attachment_filenames:
        if any(fname.lower().endswith(ext) for ext in sus_extensions):
            response["suspicious_attachments"].append(fname)

    # Add LLM-generated analysis
    response["llm_analysis"] = run_gpt_analysis(data.subject, data.body)

    return response

# Safe Browsing API check endpoint
@app.post("/check-url/")
def check_url(request: Request, url: str):
    payload = {
    "client": {
        "clientId": "phishing-detector",
        "clientVersion": "1.0"
    },
    "threatInfo": {
        "threatTypes": [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION"
        ],
        "platformTypes": ["ANY_PLATFORM"],
        "threatEntryTypes": ["URL"],
        "threatEntries": [{"url": url}]
    }
}

    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
    response = requests.post(api_url, json=payload)

    if response.status_code != 200:
        return {
            "error": f"API request failed with status code {response.status_code}",
            "details": response.text
        }

    result = response.json()

    return {
        "url_checked": url,
        "status": "dangerous" if "matches" in result else "safe",
        "threats": result.get("matches", [])
    }



