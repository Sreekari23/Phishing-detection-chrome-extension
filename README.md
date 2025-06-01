# Phishing-detection-chrome-extension

I'm working on a phishing detector on emails, as a chrome extension

✅ Today (Day 1): Setup + Feature Planning (6–8 hours)
Goals:
Finalize base repos (we’ll use 2–3)
Set up your local dev environment
Understand Chrome Extension basics
Identify and isolate features needed
Tasks:
Fork and clone these repos:
Click2Hack/Phishing-Email-Detection-Using-Machine-Learning
arvind-rs/phishing_detector
RohinSequeira/phishing_detection (withgemini)
Set up:
manifest.json
popup.html, popup.js
Gmail API or Gmail DOM scraper
Create a features checklist with columns:
Feature Name
Repo source (if any)
Implementation Status (To-do/In Progress/Done)

✅ Da 2: Gmail Integration + Suspicious Link Detection (6–7 hrs)
Goals:
Extract Gmail email body and metadata
Identify & flag suspicious URLs or domains
Tasks:
Use content.js to inject script into Gmail
Capture:
Sender
Subject
Email body
Links
Reuse Rohin’s Gemini code or your own regex pattern checker for URL detection
Create the popup alert or badge showing “Suspicious”
