# Regional-Language Phishing SMS Reporting System

A web-based phishing SMS reporting and analysis system designed to help users report suspicious SMS messages and identify potentially related phishing campaigns.

The system supports English, Hindi, and Gujarati SMS content and analyzes reported messages using phishing indicators and similarity-based campaign detection.

## 📌 Project Overview

Phishing SMS messages often impersonate banks, government services, electricity providers, delivery services, and other trusted organizations.

This project provides a centralized system where users can manually report suspicious SMS messages by entering:

- Sender ID
- SMS message
- Received date and time

The system analyzes the submitted message, extracts suspicious indicators, compares it with previously reported messages, and assigns a risk level.

## ✨ Features

- 📩 Report suspicious SMS messages
- 🌐 Support for English, Hindi, and Gujarati text
- 🔍 Detect suspicious URLs
- 📱 Detect phone numbers
- 💰 Detect money-related amounts
- ⚠️ Detect phishing-related keywords
- 🧩 Compare messages with existing phishing campaigns
- 📊 Calculate campaign similarity using MinHash
- 🔴 Classify messages as High Risk, Suspicious, or Low Risk
- 📈 Dashboard for viewing reporting statistics
- 📋 View previously submitted reports
- 🛡️ View detected phishing campaigns
- 📱 Responsive web interface

## 🧠 How It Works

The system follows these main steps:

1. User opens the **Report SMS** page.
2. User enters the sender ID, SMS text, and received time.
3. The SMS is normalized for analysis.
4. URLs, phone numbers, and monetary amounts are extracted.
5. Phishing-related keywords are checked.
6. The message is compared with existing campaign fingerprints.
7. Similarity is calculated using MinHash.
8. The system determines the risk level.
9. The report is stored in the MySQL database.
10. The user receives an analysis result.

## 🔍 Risk Detection

The system currently uses the following risk categories:

### 🔴 HIGH RISK

A message is classified as High Risk when:

- Campaign similarity is at least `0.70`, or
- Multiple phishing-related keywords are detected.

### 🟠 SUSPICIOUS

A message is classified as Suspicious when:

- Campaign similarity is at least `0.40`, or
- Phishing-related keywords are detected, or
- A URL is detected.

### 🟢 LOW RISK

A message is classified as Low Risk when no significant suspicious indicators are detected.

> These rules are part of the current project implementation and can be improved in future versions.

## 🧩 Campaign Similarity

The project uses **MinHash** to compare reported SMS messages.

Messages are converted into word-based shingles and their similarity is estimated using Jaccard similarity.

A similarity threshold of `0.70` is currently used to associate a report with an existing campaign.

This helps group similar phishing SMS messages into campaigns instead of treating every report as completely independent.

## 🛠️ Technology Stack

### Frontend

- HTML5
- CSS3
- Jinja2 Templates

### Backend

- Python
- Flask

### Database

- MySQL
- XAMPP

### Libraries

- mysql-connector-python
- datasketch

### Development Tools

- Visual Studio Code
- XAMPP
- Git
- GitHub

## 📁 Project Structure

```text
Regional-Phishing-SMS-Reporting/
│
├── app.py
├── normalizer.py
├── similarity.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── static/
│   └── css/
│       └── style.css
│
└── templates/
    ├── index.html
    ├── report.html
    ├── campaigns.html
    └── about.html