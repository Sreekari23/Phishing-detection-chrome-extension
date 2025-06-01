from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from featureExtractor import PredictURL
import validators
import os
from dotenv import load_dotenv
import google.generativeai as genai

# Initialize FastAPI app
app = FastAPI()

# Load environment variables
load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "dummy-key")
if GOOGLE_API_KEY == "dummy-key":
    print("⚠️ WARNING: Using dummy API key. Set GOOGLE_API_KEY in .env!")

# Configure Gemini
genai.configure(api_key=GOOGLE_API_KEY)
model = genai.GenerativeModel("gemini-pro")

# Enable CORS (for dev/testing from browser extensions or frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # NOTE: restrict this in production!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Root route for testing
@app.get("/")
def read_root():
    return {"message": "Phishing Detection API is running!"}

@app.get("/test-api-key")
def test_api_key():
    return {"GOOGLE_API_KEY": GOOGLE_API_KEY}

# URL-only checking route (optional)
class URLRequest(BaseModel):
    url: str

@app.post("/check-url/")
def check_url(request: URLRequest):
    print("Received URL:", request.url)
    return {"status": "safe" if "google" in request.url else "dangerous"}

# Email data model for full analysis
class EmailData(BaseModel):
    subject: str
    body: str
    urls: list[str]
    attachment_filenames: list[str]

# Your ML model
classification = PredictURL()

# LLM Analysis using Gemini
def run_gpt_analysis(subject: str, body: str, urls: list[str], attachments: list[str]) -> str:
    prompt = f"""
    Analyze the following email for phishing indicators.

    Subject: {subject}
    Body: {body}
    URLs: {urls}
    Attachment Filenames: {attachments}

    Identify any potential phishing threats, suspicious links, threat phrases, and suspicious attachments.
    Explain your reasoning in simple terms for a general user.
    """
    response = model.generate_content(prompt)
    return response.text.strip()
def run_gpt_analysis(subject: str, body: str, urls: list[str], attachments: list[str]) -> dict:
    prompt = f"""
    You are a cybersecurity analyst.

    Given the following email components:
    Subject: {subject}
    Body: {body}
    URLs: {urls}
    Attachments: {attachments}

    Perform a phishing risk analysis. Your JSON output must include:
    - "summary": One paragraph summarizing phishing risks.
    - "threat_phrases": List of suspicious or threatening phrases from the body.
    - "recommendations": List of suggested actions for the user.

    Respond strictly in JSON.
    """

    try:
        response = model.generate_content(prompt)
        import json
        return json.loads(response.text)
    except Exception as e:
        print("LLM error:", e)
        return {
            "summary": "Unable to generate analysis.",
            "threat_phrases": [],
            "recommendations": []
        }


# Main analysis endpoint
@app.post("/api/analyze")
async def analyze_email(data: EmailData):
    response = {
        "phishing_urls": [],
        "suspicious_attachments": [],
        "llm_analysis": ""
    }

    # ML-based URL classification
    for url in data.urls:
        if validators.url(url):
            verdict = classification.predict(url)
            if verdict != "Given website is a legitimate site":
                response["phishing_urls"].append({"url": url, "verdict": verdict})

    # Check for suspicious file extensions
    dangerous_exts = ['.exe', '.bat', '.cmd', '.scr', '.js', '.vbs', '.jar']
    for fname in data.attachment_filenames:
        if any(fname.lower().endswith(ext) for ext in dangerous_exts):
            response["suspicious_attachments"].append(fname)

    # Run LLM-based contextual analysis
    response["llm_analysis"] = run_gpt_analysis(
        subject=data.subject,
        body=data.body,
        urls=data.urls,
        attachments=data.attachment_filenames
    )

    return response

