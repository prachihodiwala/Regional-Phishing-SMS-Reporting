from flask import Flask, render_template, request
import mysql.connector
import re

from similarity import calculate_similarity
from normalizer import normalize_text


app = Flask(__name__)


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_db_connection():

    connection = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="phishing_sms_db"
    )

    return connection


# =========================================================
# EXTRACT SMS INDICATORS
# =========================================================

def extract_indicators(sms_text):

    # -------------------------
    # URLs
    # -------------------------

    urls = re.findall(
        r'https?://[^\s]+|www\.[^\s]+',
        sms_text,
        re.IGNORECASE
    )

    # -------------------------
    # Indian Phone Numbers
    # -------------------------

    phones = re.findall(
        r'(?:\+91[\s-]?)?[6-9]\d{9}',
        sms_text
    )

    # -------------------------
    # Money Amounts
    # -------------------------

    amounts = re.findall(
        r'(?:₹|Rs\.?|INR)\s?[\d,]+(?:\.\d{1,2})?',
        sms_text,
        re.IGNORECASE
    )

    return urls, phones, amounts


# =========================================================
# FIND MATCHING PHISHING CAMPAIGN
# =========================================================

def find_matching_campaign(db, normalized_sms):

    cursor = db.cursor()

    cursor.execute("""
        SELECT campaign_id, fingerprint
        FROM campaigns
    """)

    campaigns = cursor.fetchall()

    best_campaign_id = None
    best_similarity = 0

    for campaign_id, fingerprint in campaigns:

        similarity = calculate_similarity(
            normalized_sms,
            fingerprint
        )

        if similarity > best_similarity:

            best_similarity = similarity
            best_campaign_id = campaign_id

    cursor.close()

    # Similarity threshold
    if best_similarity >= 0.70:

        return best_campaign_id, best_similarity

    return None, best_similarity


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():

    try:

        db = get_db_connection()

        cursor = db.cursor()

        cursor.execute(
            "SELECT COUNT(*) FROM reports"
        )

        count = cursor.fetchone()[0]

        cursor.close()
        db.close()

        return render_template(
            "index.html",
            count=count,
            error=None
        )

    except Exception as e:

        return render_template(
            "index.html",
            count=0,
            error=str(e)
        )


# =========================================================
# REPORT SMS
# =========================================================

@app.route("/report", methods=["GET", "POST"])
def report():

    # =====================================================
    # GET REQUEST
    # =====================================================

    if request.method == "GET":

        return """
        <!DOCTYPE html>
        <html>

        <head>

            <title>Report Suspicious SMS</title>

            <style>

                * {
                    box-sizing: border-box;
                }

                body {
                    margin: 0;
                    font-family: Arial, sans-serif;
                    background: #f5f7fb;
                    color: #172033;
                }

                .navbar {
                    height: 70px;
                    background: #061426;
                    color: white;

                    display: flex;
                    align-items: center;
                    justify-content: space-between;

                    padding: 0 50px;
                }

                .logo {
                    font-size: 23px;
                    font-weight: bold;
                }

                .nav-links {
                    display: flex;
                    gap: 28px;
                }

                .nav-links a {
                    color: white;
                    text-decoration: none;
                    font-size: 15px;
                }

                .nav-links a:hover {
                    color: #4da3ff;
                }

                .container {
                    width: 90%;
                    max-width: 900px;
                    margin: 50px auto;

                    background: white;

                    padding: 40px;

                    border-radius: 18px;

                    box-shadow:
                        0 10px 35px rgba(0,0,0,0.08);
                }

                h1 {
                    margin-top: 0;
                    color: #061426;
                }

                .description {
                    color: #667085;
                    margin-bottom: 30px;
                    line-height: 1.6;
                }

                label {
                    display: block;
                    margin-top: 22px;
                    margin-bottom: 8px;

                    font-weight: bold;
                }

                input,
                textarea {
                    width: 100%;

                    padding: 14px;

                    border: 1px solid #d8dee8;

                    border-radius: 9px;

                    font-size: 15px;

                    outline: none;
                }

                input:focus,
                textarea:focus {
                    border-color: #247cff;

                    box-shadow:
                        0 0 0 3px rgba(36,124,255,0.10);
                }

                textarea {
                    min-height: 170px;
                    resize: vertical;
                }

                button {
                    margin-top: 28px;

                    width: 100%;

                    padding: 14px;

                    border: none;

                    border-radius: 9px;

                    background: #247cff;

                    color: white;

                    font-size: 16px;

                    font-weight: bold;

                    cursor: pointer;
                }

                button:hover {
                    background: #1769d1;
                }

                .back {
                    display: inline-block;

                    margin-top: 20px;

                    color: #247cff;

                    text-decoration: none;
                }

            </style>

        </head>


        <body>


            <div class="navbar">

                <div class="logo">
                    Phishing SMS Reporting System
                </div>

                <div class="nav-links">

                    <a href="/">Home</a>

                    <a href="/report">
                        Report SMS
                    </a>

                    <a href="/dashboard">
                        Dashboard
                    </a>

                    <a href="/reports">
                        Reports
                    </a>

                    <a href="/campaigns">
                        Campaigns
                    </a>

                    <a href="/about">
                        About
                    </a>

                </div>

            </div>


            <div class="container">

                <h1>
                    Report Suspicious SMS
                </h1>

                <p class="description">

                    Paste a suspicious SMS below.
                    The system will analyze the message,
                    detect phishing indicators and compare
                    it with previously reported campaigns.

                </p>


                <form method="POST">


                    <label>
                        Sender ID
                    </label>

                    <input
                        type="text"
                        name="sender_id"
                        placeholder="Example: VM-SBIINB"
                        required
                    >


                    <label>
                        SMS Message
                    </label>

                    <textarea
                        name="sms_text"
                        placeholder="Paste suspicious SMS here..."
                        required
                    ></textarea>


                    <label>
                        Received At
                    </label>

                    <input
                        type="datetime-local"
                        name="received_at"
                        required
                    >


                    <button type="submit">

                        Analyze & Report SMS

                    </button>


                </form>


                <a class="back" href="/">
                    ← Back to Home
                </a>

            </div>


        </body>

        </html>
        """


    # =====================================================
    # GET FORM DATA
    # =====================================================

    sender_id = request.form.get(
        "sender_id",
        ""
    ).strip()

    sms_text = request.form.get(
        "sms_text",
        ""
    ).strip()

    received_at = request.form.get(
        "received_at",
        ""
    )


    # =====================================================
    # VALIDATION
    # =====================================================

    if not sender_id or not sms_text or not received_at:

        return "Please fill all required fields."


    # =====================================================
    # NORMALIZE SMS
    # =====================================================

    normalized_sms = normalize_text(
        sms_text
    )


    # =====================================================
    # EXTRACT INDICATORS
    # =====================================================

    urls, phones, amounts = extract_indicators(
        sms_text
    )


    # =====================================================
    # DATABASE
    # =====================================================

    db = get_db_connection()

    cursor = db.cursor()


    # =====================================================
    # DEMO REPORTER
    # =====================================================

    reporter_pseudonym = "demo_user"


    cursor.execute(
        """
        SELECT reporter_id
        FROM reporters
        WHERE pseudonym = %s
        """,
        (reporter_pseudonym,)
    )


    reporter = cursor.fetchone()


    if reporter:

        reporter_id = reporter[0]

    else:

        cursor.execute(
            """
            INSERT INTO reporters
            (pseudonym, report_count)

            VALUES
            (%s, %s)
            """,

            (
                reporter_pseudonym,
                0
            )
        )

        reporter_id = cursor.lastrowid


    # =====================================================
    # FIND MATCHING CAMPAIGN
    # =====================================================

    matching_campaign_id, similarity = find_matching_campaign(
        db,
        normalized_sms
    )


    # =====================================================
    # EXISTING OR NEW CAMPAIGN
    # =====================================================

    if matching_campaign_id:

        campaign_id = matching_campaign_id

    else:

        cursor.execute(
            """
            INSERT INTO campaigns
            (fingerprint)

            VALUES
            (%s)
            """,

            (normalized_sms,)
        )

        campaign_id = cursor.lastrowid


    # =====================================================
    # SAVE REPORT
    # =====================================================

    cursor.execute(
        """
        INSERT INTO reports
        (
            reporter_id,
            sms_text,
            sender_id,
            received_at,
            campaign_id
        )

        VALUES
        (%s, %s, %s, %s, %s)
        """,

        (
            reporter_id,
            sms_text,
            sender_id,
            received_at,
            campaign_id
        )
    )


    # =====================================================
    # UPDATE REPORT COUNT
    # =====================================================

    cursor.execute(
        """
        UPDATE reporters

        SET report_count =
            report_count + 1

        WHERE reporter_id = %s
        """,

        (reporter_id,)
    )


    # =====================================================
    # SAVE URL INDICATORS
    # =====================================================

    for url in urls:

        cursor.execute(
            """
            INSERT INTO indicators
            (
                campaign_id,
                type,
                value
            )

            VALUES
            (%s, %s, %s)
            """,

            (
                campaign_id,
                "url",
                url
            )
        )


    # =====================================================
    # SAVE PHONE INDICATORS
    # =====================================================

    for phone in phones:

        cursor.execute(
            """
            INSERT INTO indicators
            (
                campaign_id,
                type,
                value
            )

            VALUES
            (%s, %s, %s)
            """,

            (
                campaign_id,
                "phone",
                phone
            )
        )


    # =====================================================
    # SAVE MONEY INDICATORS
    # =====================================================

    for amount in amounts:

        cursor.execute(
            """
            INSERT INTO indicators
            (
                campaign_id,
                type,
                value
            )

            VALUES
            (%s, %s, %s)
            """,

            (
                campaign_id,
                "amount",
                amount
            )
        )


    # =====================================================
    # COMMIT
    # =====================================================

    db.commit()

    cursor.close()

    db.close()


    # =====================================================
    # RISK DETECTION
    # =====================================================

    text_lower = sms_text.lower()


    phishing_keywords = [

        # English

        "kyc",
        "account",
        "update",
        "verify",
        "blocked",
        "expired",
        "click",
        "urgent",
        "claim",
        "winner",
        "prize",

        # Hindi

        "केवाईसी",
        "खाता",
        "अपडेट",
        "सत्यापित",
        "बंद",
        "समाप्त",
        "क्लिक",
        "तुरंत",
        "इनाम",

        # Gujarati

        "કેવાયસી",
        "ખાતું",
        "અપડેટ",
        "ચકાસો",
        "બંધ",
        "સમાપ્ત",
        "ક્લિક",
        "તાત્કાલિક",
        "ઇનામ"
    ]


    # =====================================================
    # COUNT KEYWORDS
    # =====================================================

    keyword_count = 0


    for keyword in phishing_keywords:

        if keyword in text_lower:

            keyword_count += 1


    # =====================================================
    # URL COUNT
    # =====================================================

    url_count = len(urls)


    # =====================================================
    # RISK CALCULATION
    # =====================================================

    if similarity >= 0.70 or keyword_count >= 3:

        risk_level = "HIGH RISK"

        risk_icon = "🔴"


    elif (
        similarity >= 0.40
        or keyword_count >= 1
        or url_count >= 1
    ):

        risk_level = "SUSPICIOUS"

        risk_icon = "🟠"


    else:

        risk_level = "LOW RISK"

        risk_icon = "🟢"


    # =====================================================
    # INDICATOR MESSAGES
    # =====================================================

    indicator_messages = []


    if urls:

        indicator_messages.append(
            f"🌐 {len(urls)} URL(s) detected"
        )


    if phones:

        indicator_messages.append(
            f"📱 {len(phones)} phone number(s) detected"
        )


    if amounts:

        indicator_messages.append(
            f"💰 {len(amounts)} money amount(s) detected"
        )


    if keyword_count:

        indicator_messages.append(
            f"⚠️ {keyword_count} phishing keyword(s) detected"
        )


    if similarity >= 0.70:

        indicator_messages.append(
            f"🔍 Strong campaign similarity detected"
        )


    if not indicator_messages:

        indicator_messages.append(
            "No suspicious indicators detected"
        )


    # =====================================================
    # RESULT PAGE
    # =====================================================

    return render_template(
        "report.html",

        risk_level=risk_level,

        risk_icon=risk_icon,

        campaign_id=campaign_id,

        similarity=similarity,

        urls=urls,

        phones=phones,

        amounts=amounts,

        keyword_count=keyword_count,

        indicator_messages=indicator_messages
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    db = get_db_connection()

    cursor = db.cursor()


    # Total reports

    cursor.execute(
        "SELECT COUNT(*) FROM reports"
    )

    total_reports = cursor.fetchone()[0]


    # Campaigns

    cursor.execute(
        "SELECT COUNT(*) FROM campaigns"
    )

    active_campaigns = cursor.fetchone()[0]


    # Indicators

    cursor.execute(
        "SELECT COUNT(*) FROM indicators"
    )

    total_indicators = cursor.fetchone()[0]


    # Reporters

    cursor.execute(
        "SELECT COUNT(*) FROM reporters"
    )

    active_reporters = cursor.fetchone()[0]


    # Top campaigns

    cursor.execute(
        """
        SELECT
            c.campaign_id,
            c.fingerprint,
            COUNT(r.campaign_id)

        FROM campaigns c

        LEFT JOIN reports r
        ON c.campaign_id = r.campaign_id

        GROUP BY
            c.campaign_id,
            c.fingerprint

        ORDER BY
            COUNT(r.campaign_id) DESC

        LIMIT 5
        """
    )


    top_campaigns = cursor.fetchall()

        # Daily report counts for the last 6 days
    cursor.execute("""
        SELECT DATE(received_at), COUNT(*)
        FROM reports
        WHERE received_at >= CURDATE() - INTERVAL 5 DAY
        GROUP BY DATE(received_at)
        ORDER BY DATE(received_at)
    """)

    daily_data = cursor.fetchall()

    daily_counts = {}

    for report_date, count in daily_data:
        daily_counts[str(report_date)] = count


    # Create last 6 days
    from datetime import date, timedelta

    today = date.today()

    chart_data = []

    for i in range(5, -1, -1):

        current_date = today - timedelta(days=i)

        date_key = str(current_date)

        count = daily_counts.get(date_key, 0)

        chart_data.append(
            (current_date, count)
        )


    max_count = max(
        [count for _, count in chart_data] + [1]
    )


    chart_bars = ""

    chart_labels = ""

    for current_date, count in chart_data:

        height = (count / max_count) * 100

        chart_bars += f"""
            <div class="bar" style="height: {height}%;">
                <span>{count}</span>
            </div>
        """

        if current_date == today:
            label = "Today"
        else:
            label = current_date.strftime("%d %b")

        chart_labels += f"""
            <span>{label}</span>
        """


    cursor.close()

    db.close()


    # =====================================================
    # DASHBOARD HTML
    # =====================================================

    campaign_rows = ""


    for row in top_campaigns:

        campaign_rows += f"""
        <div class="campaign">

            <div class="campaign-name">
                {row[1]}
            </div>

            <div class="campaign-count">
                {row[2]} reports
            </div>

        </div>
        """


    return f"""
<!DOCTYPE html>

<html>

<head>

<title>
Dashboard - Phishing SMS Reporting System
</title>


<style>

* {{
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}}

body {{
    font-family: Arial, sans-serif;
    background: #f5f7fb;
    color: #172033;
    overflow-x: hidden;
}}

/* ================= NAVBAR ================= */

.navbar {{
    min-height: 70px;
    background: #061426;
    color: white;

    display: flex;
    align-items: center;
    justify-content: space-between;

    padding: 15px 4%;
    gap: 20px;
}}

.logo {{
    font-size: 23px;
    font-weight: bold;
    white-space: nowrap;
}}

.nav-links {{
    display: flex;
    align-items: center;
    justify-content: flex-end;
    flex-wrap: wrap;
    gap: 10px 25px;
}}

.nav-links a {{
    color: white;
    text-decoration: none;
    font-size: 15px;
    font-weight: 600;
    transition: 0.3s;
}}

.nav-links a:hover {{
    color: #4da3ff;
}}


/* ================= CONTAINER ================= */

.container {{
    width: 92%;
    max-width: 1250px;
    margin: 45px auto;
}}

.title h1 {{
    font-size: 34px;
    margin-bottom: 8px;
}}

.title p {{
    color: #687386;
    font-size: 17px;
    line-height: 1.6;
    margin-bottom: 30px;
}}


/* ================= STAT CARDS ================= */

.cards {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 22px;
    margin-bottom: 30px;
}}

.card {{
    background: white;
    padding: 28px;
    border-radius: 15px;
    border: 1px solid #e5e9ef;
    box-shadow: 0 7px 25px rgba(0,0,0,0.07);
    min-width: 0;
}}

.card-title {{
    color: #687386;
    font-size: 15px;
    margin-bottom: 15px;
}}

.card-number {{
    font-size: 38px;
    font-weight: bold;
    color: #061b38;
    word-break: break-word;
}}

.card-description {{
    margin-top: 8px;
    color: #8993a4;
    font-size: 14px;
    line-height: 1.5;
}}


/* ================= DASHBOARD GRID ================= */

.dashboard-grid {{
    display: grid;
    grid-template-columns: 1.5fr 1fr;
    gap: 25px;
}}

.section {{
    background: white;
    padding: 28px;
    border-radius: 15px;
    border: 1px solid #e5e9ef;
    box-shadow: 0 7px 25px rgba(0,0,0,0.07);
    min-width: 0;
}}

.section h2 {{
    margin-bottom: 25px;
    font-size: 22px;
}}


/* ================= CHART ================= */

.chart {{
    height: 250px;

    display: flex;
    align-items: flex-end;
    justify-content: space-around;

    gap: 15px;

    border-bottom: 1px solid #ddd;

    padding: 20px 10px 0;
    overflow: hidden;
}}

.bar {{
    width: 45px;
    max-width: 12%;

    background: #247cff;

    border-radius: 7px 7px 0 0;

    position: relative;

    min-height: 20px;

    transition: 0.3s;
}}

.bar:hover {{
    opacity: 0.85;
}}

.bar span {{
    position: absolute;
    top: -25px;

    width: 100%;

    text-align: center;

    font-weight: bold;
    font-size: 13px;
}}

.chart-labels {{
    display: flex;
    justify-content: space-around;

    margin-top: 12px;

    color: #687386;
    font-size: 12px;

    gap: 5px;
}}


/* ================= TOP CAMPAIGNS ================= */

.campaign {{
    display: flex;
    justify-content: space-between;
    align-items: center;

    gap: 15px;

    padding: 16px 0;

    border-bottom: 1px solid #eeeeee;
}}

.campaign:last-child {{
    border-bottom: none;
}}

.campaign-name {{
    font-weight: bold;

    max-width: 72%;

    overflow: hidden;
    white-space: nowrap;
    text-overflow: ellipsis;
}}

.campaign-count {{
    background: #e8f1ff;
    color: #1769d1;

    padding: 7px 11px;

    border-radius: 20px;

    font-size: 12px;
    font-weight: bold;

    white-space: nowrap;
}}


/* ================= TABLET ================= */

@media (max-width: 1000px) {{

    .navbar {{
        flex-direction: column;
        padding: 20px;
        gap: 18px;
    }}

    .logo {{
        text-align: center;
        font-size: 21px;
    }}

    .nav-links {{
        width: 100%;
        justify-content: center;
        gap: 10px 18px;
    }}

    .cards {{
        grid-template-columns: repeat(2, 1fr);
    }}

    .dashboard-grid {{
        grid-template-columns: 1fr;
    }}

    .container {{
        width: 94%;
        margin: 35px auto;
    }}

}}


/* ================= MOBILE ================= */

@media (max-width: 600px) {{

    .navbar {{
        padding: 18px 14px;
    }}

    .logo {{
        font-size: 18px;
        line-height: 1.4;
        white-space: normal;
        text-align: center;
    }}

    .nav-links {{
        gap: 9px 13px;
    }}

    .nav-links a {{
        font-size: 12px;
    }}

    .container {{
        width: 94%;
        margin: 25px auto;
    }}

    .title h1 {{
        font-size: 26px;
        line-height: 1.3;
    }}

    .title p {{
        font-size: 14px;
        margin-bottom: 22px;
    }}

    /* Cards become one column */

    .cards {{
        grid-template-columns: 1fr;
        gap: 15px;
        margin-bottom: 20px;
    }}

    .card {{
        padding: 20px;
        border-radius: 12px;
    }}

    .card-title {{
        font-size: 14px;
        margin-bottom: 10px;
    }}

    .card-number {{
        font-size: 32px;
    }}

    .card-description {{
        font-size: 13px;
    }}

    /* Sections */

    .dashboard-grid {{
        grid-template-columns: 1fr;
        gap: 18px;
    }}

    .section {{
        padding: 20px;
        border-radius: 12px;
    }}

    .section h2 {{
        font-size: 20px;
        margin-bottom: 20px;
    }}

    /* Chart */

    .chart {{
        height: 220px;
        gap: 8px;
        padding: 20px 5px 0;
    }}

    .bar {{
        width: 30px;
        max-width: 14%;
    }}

    .bar span {{
        font-size: 11px;
        top: -22px;
    }}

    .chart-labels {{
        font-size: 10px;
        gap: 2px;
    }}

    /* Campaigns */

    .campaign {{
        padding: 13px 0;
        gap: 10px;
    }}

    .campaign-name {{
        max-width: 65%;
        font-size: 13px;
    }}

    .campaign-count {{
        padding: 6px 9px;
        font-size: 11px;
    }}

}}


/* ================= SMALL MOBILE ================= */

@media (max-width: 400px) {{

    .navbar {{
        padding: 16px 10px;
    }}

    .logo {{
        font-size: 16px;
    }}

    .nav-links {{
        gap: 8px 10px;
    }}

    .nav-links a {{
        font-size: 10px;
    }}

    .container {{
        width: 94%;
        margin: 22px auto;
    }}

    .title h1 {{
        font-size: 23px;
    }}

    .title p {{
        font-size: 13px;
    }}

    .card {{
        padding: 16px;
    }}

    .card-number {{
        font-size: 29px;
    }}

    .section {{
        padding: 16px;
    }}

    .section h2 {{
        font-size: 18px;
    }}

    .chart {{
        height: 190px;
        gap: 4px;
    }}

    .bar {{
        width: 24px;
    }}

    .chart-labels {{
        font-size: 9px;
    }}

    .campaign-name {{
        font-size: 12px;
    }}

    .campaign-count {{
        font-size: 10px;
        padding: 5px 7px;
    }}

}}

</style>
</head>


<body>


<div class="navbar">

    <div class="logo">
        Phishing SMS Reporting System
    </div>


    <div class="nav-links">

        <a href="/">Home</a>

        <a href="/report">
            Report SMS
        </a>

        <a href="/dashboard">
            Dashboard
        </a>

        <a href="/reports">
            Reports
        </a>

        <a href="/campaigns">
            Campaigns
        </a>

        <a href="/about">
            About
        </a>

    </div>

</div>


<div class="container">


    <div class="title">

        <h1>
            Dashboard Overview
        </h1>

        <p>
            Monitor phishing SMS reports
            and campaigns
        </p>

    </div>


    <div class="cards">


        <div class="card">

            <div class="card-title">
                Total Reports
            </div>

            <div class="card-number">
                {total_reports}
            </div>

            <div class="card-description">
                SMS reported
            </div>

        </div>


        <div class="card">

            <div class="card-title">
                Active Campaigns
            </div>

            <div class="card-number">
                {active_campaigns}
            </div>

            <div class="card-description">
                Phishing campaigns
            </div>

        </div>


        <div class="card">

            <div class="card-title">
                Total Indicators
            </div>

            <div class="card-number">
                {total_indicators}
            </div>

            <div class="card-description">
                URLs, phones & amounts
            </div>

        </div>


        <div class="card">

            <div class="card-title">
                Active Reporters
            </div>

            <div class="card-number">
                {active_reporters}
            </div>

            <div class="card-description">
                Community reporters
            </div>

        </div>


    </div>


    <div class="dashboard-grid">


        <div class="section">

            <h2>
                Reports Overview
            </h2>


            <div class="chart">

               {chart_bars}

            </div>

            <div class="chart-labels">

              {chart_labels}

            </div>
        </div>


        <div class="section">

            <h2>
                Top Campaigns
            </h2>

            {campaign_rows}

        </div>


    </div>


</div>


</body>

</html>
"""


# =========================================================
# REPORTS PAGE
# =========================================================

@app.route("/reports")
def reports():

    db = get_db_connection()

    cursor = db.cursor()


    cursor.execute(
        """
        SELECT

            r.report_id,

            r.sender_id,

            r.sms_text,

            r.campaign_id,

            r.received_at,

            rp.pseudonym

        FROM reports r

        LEFT JOIN reporters rp

        ON r.reporter_id =
           rp.reporter_id

        ORDER BY
            r.report_id DESC
        """
    )


    reports_data = cursor.fetchall()


    cursor.close()

    db.close()


    rows = ""


    for report_data in reports_data:

        report_id = report_data[0]

        sender_id = report_data[1]

        sms_text = report_data[2]

        campaign_id = report_data[3]

        received_at = report_data[4]

        reporter = (
            report_data[5]
            if report_data[5]
            else "Unknown"
        )


        if len(sms_text) > 60:

            sms_preview = (
                sms_text[:60] + "..."
            )

        else:

            sms_preview = sms_text


        rows += f"""

        <tr>

            <td>{report_id}</td>

            <td>{sender_id}</td>

            <td>{sms_preview}</td>

            <td>{campaign_id}</td>

            <td>{received_at}</td>

            <td>{reporter}</td>

        </tr>

        """


    return f"""
<!DOCTYPE html>

<html>

<head>

<title>
Reports - Phishing SMS Reporting System
</title>



<style>

* {{
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}}

body {{
    font-family: Arial, sans-serif;
    background: #f5f7fb;
    color: #172033;
    overflow-x: hidden;
}}


/* =========================
   NAVBAR
========================= */

.navbar {{
    min-height: 70px;
    background: #061426;
    color: white;

    display: flex;
    align-items: center;
    justify-content: space-between;

    padding: 15px 4%;
    gap: 20px;
}}

.logo {{
    font-size: 23px;
    font-weight: bold;
    white-space: nowrap;
}}

.nav-links {{
    display: flex;
    align-items: center;
    justify-content: flex-end;
    flex-wrap: wrap;
    gap: 10px 25px;
}}

.nav-links a {{
    color: white;
    text-decoration: none;
    font-size: 15px;
    font-weight: 600;
    transition: 0.3s;
}}

.nav-links a:hover {{
    color: #4da3ff;
}}


/* =========================
   MAIN CONTAINER
========================= */

.container {{
    width: 92%;
    max-width: 1250px;
    margin: 45px auto;
}}

h1 {{
    font-size: 34px;
    margin-bottom: 10px;
}}

.subtitle {{
    color: #687386;
    margin-bottom: 30px;
    font-size: 16px;
    line-height: 1.6;
}}


/* =========================
   TABLE CARD
========================= */

.table-card {{
    background: white;
    padding: 25px;

    border-radius: 15px;

    box-shadow:
        0 7px 25px rgba(0,0,0,0.07);

    overflow-x: auto;
}}


/* =========================
   SEARCH
========================= */

.search {{
    width: 350px;
    max-width: 100%;

    padding: 13px 15px;
    margin-bottom: 20px;

    border: 1px solid #d8dee8;
    border-radius: 8px;

    font-size: 15px;
    outline: none;
}}

.search:focus {{
    border-color: #247cff;

    box-shadow:
        0 0 0 3px rgba(36,124,255,0.10);
}}


/* =========================
   TABLE
========================= */

table {{
    width: 100%;
    min-width: 800px;

    border-collapse: collapse;
}}

th {{
    background: #f8f9fb;
    color: #596579;

    text-align: left;

    padding: 15px;

    font-size: 14px;
    white-space: nowrap;
}}

td {{
    padding: 15px;

    border-bottom:
        1px solid #eeeeee;

    font-size: 14px;

    vertical-align: top;
}}

tr:hover {{
    background: #fafcff;
}}


/* =========================
   TABLET
========================= */

@media (max-width: 900px) {{

    .navbar {{
        flex-direction: column;
        padding: 20px;
        gap: 18px;
    }}

    .logo {{
        text-align: center;
        font-size: 21px;
    }}

    .nav-links {{
        width: 100%;
        justify-content: center;
        gap: 10px 18px;
    }}

    .container {{
        width: 94%;
        margin: 35px auto;
    }}

    h1 {{
        font-size: 30px;
    }}

    .table-card {{
        padding: 20px;
    }}

}}


/* =========================
   MOBILE
========================= */

@media (max-width: 600px) {{

    .navbar {{
        padding: 18px 14px;
    }}

    .logo {{
        font-size: 18px;
        line-height: 1.4;
        white-space: normal;
        text-align: center;
    }}

    .nav-links {{
        gap: 9px 13px;
    }}

    .nav-links a {{
        font-size: 12px;
    }}

    .container {{
        width: 94%;
        margin: 25px auto;
    }}

    h1 {{
        font-size: 25px;
    }}

    .subtitle {{
        font-size: 14px;
        margin-bottom: 22px;
    }}

    .table-card {{
        padding: 15px;
        border-radius: 12px;
    }}

    .search {{
        width: 100%;
        padding: 12px;
        font-size: 14px;
    }}

    /*
       Table remains horizontally scrollable
       instead of breaking the layout.
    */

    table {{
        min-width: 760px;
    }}

    th {{
        padding: 12px;
        font-size: 13px;
    }}

    td {{
        padding: 12px;
        font-size: 13px;
    }}
}}


/* =========================
   SMALL MOBILE
========================= */

@media (max-width: 400px) {{

    .navbar {{
        padding: 16px 10px;
    }}

    .logo {{
        font-size: 16px;
    }}

    .nav-links {{
        gap: 8px 10px;
    }}

    .nav-links a {{
        font-size: 10px;
    }}

    h1 {{
        font-size: 22px;
    }}

    .subtitle {{
        font-size: 13px;
    }}

    .table-card {{
        padding: 12px;
    }}

}}

</style>

</head>


<body>


<div class="navbar">

    <div class="logo">
        Phishing SMS Reporting System
    </div>


    <div class="nav-links">

        <a href="/">Home</a>

        <a href="/report">
            Report SMS
        </a>

        <a href="/dashboard">
            Dashboard
        </a>

        <a href="/reports">
            Reports
        </a>

        <a href="/campaigns">
            Campaigns
        </a>

        <a href="/about">
            About
        </a>

    </div>

</div>


<div class="container">

    <h1>
        All Reports
    </h1>

    <p class="subtitle">
        View suspicious SMS reports
        submitted by the community
    </p>


    <div class="table-card">


        <input
            class="search"
            id="search"
            placeholder="Search reports..."
            onkeyup="searchReports()"
        >


        <table id="reportsTable">

            <thead>

                <tr>

                    <th>ID</th>

                    <th>Sender ID</th>

                    <th>SMS Preview</th>

                    <th>Campaign ID</th>

                    <th>Date & Time</th>

                    <th>Reporter</th>

                </tr>

            </thead>


            <tbody>

                {rows}

            </tbody>

        </table>


    </div>

</div>


<script>

function searchReports() {{

    let input =
        document
        .getElementById("search")
        .value
        .toLowerCase();


    let rows =
        document
        .querySelectorAll(
            "#reportsTable tbody tr"
        );


    rows.forEach(function(row) {{

        let text =
            row.innerText.toLowerCase();


        if(text.includes(input)) {{

            row.style.display = "";

        }}

        else {{

            row.style.display = "none";

        }}

    }});

}}

</script>


</body>

</html>
"""


# =========================================================
# CAMPAIGNS PAGE
# =========================================================

@app.route("/campaigns")
def campaigns():

    db = get_db_connection()

    cursor = db.cursor()


    cursor.execute(
        """
        SELECT

            c.campaign_id,

            c.fingerprint,

            c.first_seen,

            COUNT(r.report_id)

        FROM campaigns c

        LEFT JOIN reports r

        ON c.campaign_id =
           r.campaign_id

        GROUP BY

            c.campaign_id,

            c.fingerprint,

            c.first_seen

        ORDER BY
            c.campaign_id
        """
    )


    campaigns_data = cursor.fetchall()


    cursor.close()

    db.close()


    return render_template(
        "campaigns.html",
        campaigns=campaigns_data
    )


# =========================================================
# ABOUT PAGE
# =========================================================

@app.route("/about")
def about():

    return render_template(
        "about.html"
    )


# =========================================================
# RUN FLASK APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )