from flask import Flask, render_template_string
from SmartApi import SmartConnect
import pyotp
import requests
import pandas as pd
from datetime import datetime

# ==============================
# 🔐 YOUR CREDENTIALS
# ==============================
API_KEY = "8zv76K9h"
CLIENT_CODE = "M700579"
PIN = "7869"
TOTP_TOKEN = "RUEL32R7OCR3FY6KVRM3IIXV6I"

app = Flask(__name__)

# ==============================
# Angel Login Function
# ==============================
def angel_login():
    smartApi = SmartConnect(API_KEY)
    totp = pyotp.TOTP(TOTP_TOKEN).now()
    data = smartApi.generateSession(CLIENT_CODE, PIN, totp)

    if data['status'] is False:
        raise Exception("Login Failed")

    return smartApi


# ==============================
# Get NIFTY Option Chain
# ==============================
def get_nifty_option_chain():
    smartApi = angel_login()

    # Get Spot Price
    ltp_data = smartApi.ltpData("NSE", "NIFTY", "99926000")
    spot = ltp_data['data']['ltp']

    # Download Instrument Master
    url = "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json"
    response = requests.get(url)
    instruments = response.json()
    df = pd.DataFrame(instruments)

    # Filter NIFTY Options
    df = df[(df['name'] == 'NIFTY') & (df['instrumenttype'] == 'OPTIDX')]
    df['expiry'] = pd.to_datetime(df['expiry'])

    nearest_expiry = min(df['expiry'].unique())
    df = df[df['expiry'] == nearest_expiry]

    df['strike'] = df['strike'].astype(float)

    # ATM Calculation
    atm = round(spot / 50) * 50

    # Filter ± 5 strikes
    df = df[df['strike'].between(atm - 250, atm + 250)]

    option_chain = []

    for _, row in df.iterrows():
        try:
            ltp = smartApi.ltpData("NFO", row['tradingsymbol'], row['symboltoken'])
            option_chain.append({
                "symbol": row['tradingsymbol'],
                "strike": row['strike'],
                "ltp": ltp['data']['ltp']
            })
        except:
            continue

    return spot, nearest_expiry.date(), sorted(option_chain, key=lambda x: x['strike'])


# ==============================
# Flask Route
# ==============================
@app.route("/")
def home():
    spot, expiry, chain = get_nifty_option_chain()

    html = """
    <h2>NIFTY 50 Option Chain</h2>
    <h3>Spot Price: {{spot}}</h3>
    <h3>Expiry: {{expiry}}</h3>
    <table border="1" cellpadding="5">
        <tr>
            <th>Symbol</th>
            <th>Strike</th>
            <th>LTP</th>
        </tr>
        {% for row in chain %}
        <tr>
            <td>{{row.symbol}}</td>
            <td>{{row.strike}}</td>
            <td>{{row.ltp}}</td>
        </tr>
        {% endfor %}
    </table>
    """

    return render_template_string(html, spot=spot, expiry=expiry, chain=chain)


# ==============================
# Run Flask
# ==============================
if __name__ == "__main__":
    app.run(debug=True)
