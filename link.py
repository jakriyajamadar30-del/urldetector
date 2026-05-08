# app.py

from flask import Flask, render_template, request
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from urllib.parse import urlparse
import re

app = Flask(__name__)

# ---------------- DATASET ----------------

data = {

    "url":[

# ---------------- SAFE LINKS ----------------

"https://google.com",
"https://gmail.com",
"https://youtube.com",
"https://github.com",
"https://amazon.in",
"https://wikipedia.org",
"https://linkedin.com",
"https://microsoft.com",
"https://apple.com",
"https://openai.com",
"https://paypal.com",
"https://instagram.com",
"https://facebook.com",
"https://twitter.com",
"https://reddit.com",
"https://flipkart.com",
"https://spotify.com",
"https://whatsapp.com",
"https://telegram.org",
"https://zoom.us",
"https://sbi.co.in",
"https://hdfcbank.com",
"https://icicibank.com",
"https://uidai.gov.in",
"https://irctc.co.in",
"https://python.org",
"https://react.dev",
"https://coursera.org",
"https://udemy.com",
"https://bbc.com",
"https://mahanmk.com",




# ---------------- TYPO / FAKE ----------------

"https://mircosoft.com",
"https://micros0ft.com",
"https://rnicrosoft.com",
"https://g00gle.com",
"https://faceb00k.com",
"https://paypa1.com",


# ---------------- PHISHING LINKS ----------------

"https://google-login-warning.com",
"https://google-account-security.xyz",
"https://gmail-password-reset-alert.net",
"https://youtube-premium-free.xyz",
"https://github-security-check.net",
"https://amazon-prize-claim.com",
"https://amazon-login-security.net",
"https://linkedin-account-warning.net",
"https://microsoft-security-account.com",
"https://paypal-secure-login.com",
"https://instagram-followers-free.xyz",
"https://facebook-security-alert.net",
"https://bank-login-warning.net",
"https://verify-account-security.net",
"https://claim-prize-now.xyz",
"https://secure-login-bank.com",
"https://google-free-reward.xyz",
"https://paypal-account-update.com",
"https://netflix-billing-warning.net",
"https://spotify-free-premium.xyz",
"https://telegram-security-alert.net",
"https://zoom-account-warning.com",
"https://free-mobile-recharge.xyz",
"https://crypto-free-gift.net",
"https://google.verify-login-alert.com",
"https://microsoft.security-update-warning.net",
"https://paypal.verify-account-security.com",
"https://google---security---warning.xyz",
"https://amazon--secure-login.net",
"https://github_account_verify.xyz",
"https://login-free-reward-security.net",
"https://paypal@security-alert.com",
"https://google.security.account.verify.xyz",
"https://g00gle-account-warning.xyz",
"https://paypa1-login-security.net",
"https://amazon-free-reward.xyz",


],

"label":[

# SAFE = 0
0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,
0,

# TYPO / FAKE = 1
1,1,1,1,1,1,

# PHISHING = 1
1,1,1,1,1,1,1,1,1,1,
1,1,1,1,1,1,1,1,1,1,
1,1,1,1,1,1,1,1,1,1,
1,1,1,1,1,1,
]

}

df = pd.DataFrame(data)

# ---------------- MACHINE LEARNING ----------------

vectorizer = TfidfVectorizer(
    analyzer="char_wb",
    ngram_range=(3,6)
)

X = vectorizer.fit_transform(df["url"])

model = LogisticRegression(max_iter=5000)

model.fit(X, df["label"])

# ---------------- TRUSTED DOMAINS ----------------

trusted_domains = [
    "google.com",
    "youtube.com",
    "github.com",
    "amazon.in",
    "microsoft.com",
    "apple.com",
    "paypal.com",
    "facebook.com",
    "instagram.com",
    "openai.com",
    "sbi.co.in",
    "hdfcbank.com",
    "uidai.gov.in",
    "irctc.co.in",
    "python.org",
    "mahanmk.com",
    "microsoftonline.com",
    "login.microsoftonline.com"
]

# ---------------- SUSPICIOUS WORDS ----------------

suspicious_words = [
    "login",
    "verify",
    "security",
    "claim",
    "free",
    "warning",
    "reward",
    "alert",
    "gift",
    "premium",
    "billing",
    "reset",
    "password",
    "otp",
    "bonus",
    "win",
    "prize",
    "account",
    "secure"
]

# ---------------- DANGEROUS DOMAINS ----------------

dangerous_domains = [
    ".xyz",
    ".tk",
    ".top",
    ".gq",
    ".test"
]

# ---------------- URL SHORTENERS ----------------

shorteners = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co"
]

# ---------------- PHISHING SCORE ----------------

def phishing_score(url):

    score = 0

    url_lower = url.lower()

    parsed = urlparse(url_lower)

    domain = parsed.netloc.replace("www.", "")

    path = parsed.path.lower()

    # trusted domain
    if domain in trusted_domains:
        return 0
    for trusted in trusted_domains:
        if domain.endswith("."+ trusted):
           return 0 
    # suspicious words
    for word in suspicious_words:

        if word in domain:

            if word in ["login", "verify", "password", "otp"]:
                score += 4
            else:
                score += 2

    # suspicious path
    for word in suspicious_words:

        if word in path:
            score += 1

    # hyphens
    hyphen_count = domain.count("-")

    if hyphen_count == 1:
        score += 1

    elif hyphen_count == 2:
        score += 3

    elif hyphen_count >= 3:
        score += 5

    # repeated hyphen
    if "--" in domain:
        score += 6

    if "---" in domain:
        score += 8

    # many dots
    dot_count = domain.count(".")

    if dot_count >= 3:
        score += 4

    # underscore
    if "_" in domain:
        score += 5

    # @ symbol
    if "@" in url_lower:
        score += 10

    # dangerous domains
    for d in dangerous_domains:

        if domain.endswith(d):
            score += 7

    # url shorteners
    for short in shorteners:

        if short in domain:
            score += 2

    # dangerous files
    dangerous_files = [
        ".exe",
        ".apk",
        ".bat",
        ".zip"
    ]

    for file in dangerous_files:

        if file in path:
            score += 7

    # IP address links
    if re.search(r"\d+\.\d+\.\d+\.\d+", domain):
        score += 10

    # fake trusted brands
    for trusted in trusted_domains:

        brand = trusted.split(".")[0]

        # google-login-alert.com
        if brand in domain:

            if domain != trusted and not domain.endswith("." + trusted):
                score += 8

        # g00gle
        if brand.replace("o", "0") in domain:
            score += 8

        # rnicrosoft
        if brand.replace("m", "rn") in domain:
            score += 8

        # paypa1
        if brand.replace("l", "1") in domain:
            score += 8

    return score

# ---------------- FLASK ----------------

@app.route("/", methods=["GET", "POST"])

def home():

    result = ""
    message = ""
    url = ""
    risk_score = 0

    if request.method == "POST":

        original_url = request.form["url"].strip()

        url = original_url

        # auto add https
        if not url.startswith("http://") and not url.startswith("https://"):

            url = "https://" + url

        # validation
        domain_check = re.match(
            r"^https?://[A-Za-z0-9._@%/\-=]+\.[A-Za-z]{2,}",
            url
        )

        if not domain_check:

            result = "⚠️ Link is INVALID"
            message = "Enter valid website link"

        else:

            parsed = urlparse(url)

            domain = parsed.netloc.replace("www.", "")

            # ML prediction
            X_test = vectorizer.transform([url])

            probability = model.predict_proba(X_test)[0][1]

            # phishing score
            risk_score = phishing_score(url)

            # safe extensions
            safe_extensions = [
                ".gov.in",
                ".edu",
                ".org",
                ".ac.in"
            ]

            for ext in safe_extensions:

                if domain.endswith(ext):
                    risk_score -= 2

            # avoid negative
            if risk_score < 0:
                risk_score = 0

            # trusted subdomain
            trusted_subdomain = False

            for trusted in trusted_domains:

                if domain == trusted or domain.endswith("." + trusted):
                    trusted_subdomain = True
                    break

            # dangerous patterns
            dangerous_pattern = (
                "@" in url
                or ".xyz" in domain
                or "--" in domain
                or "login" in domain
                or "verify" in domain
                or "password" in domain
                or "otp" in domain
            )

            # FINAL DETECTION

            if (

                probability >= 0.90

                or

                (probability >= 0.70 and risk_score >= 5)

                or

                risk_score >= 8

                or

                (dangerous_pattern and risk_score >= 5)

            ):

                result = "⚠️ Warning- Link is PHISHING"
                message = "❌ Do not click on the link"

            elif (

                trusted_subdomain

                or

                (
                    probability < 0.50
                    and risk_score <= 3
                )

            ):

                result = "👍 Link is SAFE"
                message = "Secure to browse or click"

            else:

                result = "⚠️Warning-Phishing Link"
                message = "❌ Do not click on the link"

    return render_template(
        "index.html",
        result=result,
        message=message,
        score=risk_score,
        url=original_url if request.method == "POST" else ""
    )

# ---------------- RUN ----------------

if __name__ == "__main__":

    app.run(debug=True)