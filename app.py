from fyers_apiv3 import fyersModel
from flask import Flask, request, render_template_string, jsonify, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import webbrowser
import pandas as pd
import os
import threading
import time
import json
import requests
import hashlib
from datetime import datetime
# Angel One Imports
from SmartApi import SmartConnect
import pyotp

app = Flask(__name__)
app.secret_key = "sajid_secret_key_change_this"

# ===== API Secrets =====
MSTOCK_API_SECRET = '<your_mstock_api_secret_here>'

# Text files for storing data
USERS_FILE = "users.txt"
CREDENTIALS_FILE = "user_credentials.txt"
ANGEL_MASTER_FILE = "angel_master.json"

# Initialize files
def init_files():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'w') as f: f.write("")
    if not os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, 'w') as f: f.write("")

init_files()

# ---- User Management Functions ----
def save_user(username, password, email):
    with open(USERS_FILE, 'a') as f:
        hashed_pw = generate_password_hash(password)
        f.write(f"{username}|{hashed_pw}|{email}\n")

def get_user(username):
    if not os.path.exists(USERS_FILE): return None
    with open(USERS_FILE, 'r') as f:
        for line in f:
            if line.strip():
                parts = line.strip().split('|')
                if len(parts) >= 3 and parts[0] == username:
                    return {'username': parts[0], 'password': parts[1], 'email': parts[2]}
    return None

def verify_user(username, password):
    user = get_user(username)
    if user and check_password_hash(user['password'], password): return user
    return None

def save_user_credentials(username, client_id=None, secret_key=None, auth_code=None, 
                          mstock_api_key=None, 
                          angel_api_key=None, angel_client_code=None, angel_pin=None, angel_totp=None):
    credentials = {}
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, 'r') as f:
            for line in f:
                if line.strip():
                    parts = line.strip().split('|')
                    # Format: user|fyers_id|fyers_secret|fyers_auth|mstock_key|angel_key|angel_client|angel_pin|angel_totp
                    if len(parts) >= 9:
                        credentials[parts[0]] = {
                            'client_id': parts[1], 'secret_key': parts[2], 'auth_code': parts[3],
                            'mstock_api_key': parts[4], 'angel_api_key': parts[5], 
                            'angel_client_code': parts[6], 'angel_pin': parts[7], 'angel_totp': parts[8]
                        }

    if username not in credentials:
        credentials[username] = {'client_id': '', 'secret_key': '', 'auth_code': '', 'mstock_api_key': '', 
                                 'angel_api_key': '', 'angel_client_code': '', 'angel_pin': '', 'angel_totp': ''}

    # Update provided fields
    if client_id: credentials[username]['client_id'] = client_id
    if secret_key: credentials[username]['secret_key'] = secret_key
    if auth_code: credentials[username]['auth_code'] = auth_code
    if mstock_api_key: credentials[username]['mstock_api_key'] = mstock_api_key
    if angel_api_key: credentials[username]['angel_api_key'] = angel_api_key
    if angel_client_code: credentials[username]['angel_client_code'] = angel_client_code
    if angel_pin: credentials[username]['angel_pin'] = angel_pin
    if angel_totp: credentials[username]['angel_totp'] = angel_totp

    with open(CREDENTIALS_FILE, 'w') as f:
        for user, creds in credentials.items():
            f.write(f"{user}|{creds['client_id']}|{creds['secret_key']}|{creds['auth_code']}|{creds['mstock_api_key']}|{creds['angel_api_key']}|{creds['angel_client_code']}|{creds['angel_pin']}|{creds['angel_totp']}\n")

def get_user_credentials(username):
    if not os.path.exists(CREDENTIALS_FILE): return None
    with open(CREDENTIALS_FILE, 'r') as f:
        for line in f:
            if line.strip():
                parts = line.strip().split('|')
                if len(parts) >= 9 and parts[0] == username:
                    return {
                        'client_id': parts[1], 'secret_key': parts[2], 'auth_code': parts[3],
                        'mstock_api_key': parts[4], 'angel_api_key': parts[5],
                        'angel_client_code': parts[6], 'angel_pin': parts[7], 'angel_totp': parts[8]
                    }
    return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session: return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

# ---- Session & Broker Objects ----
user_sessions = {}
angel_instruments_df = None

def get_user_session(username):
    if username not in user_sessions:
        user_sessions[username] = {
            'fyers': None, 'atm_strike': None, 'initial_data': None,
            'atm_ce_plus20': 20, 'atm_pe_plus20': 20, 'symbol_prefix': 'NSE:NIFTY25',
            'selected_index': 'NSE:NIFTY50-INDEX', 'signals': [], 'placed_orders': set(),
            'bot_running': False, 'bot_thread': None, 'redirect_uri': f'http://127.0.0.1:5000/callback/{username}',
            'quantity': 75, 'ce_offset': -300, 'pe_offset': 300,
            'mstock_access_token': None, 'mstock_refresh_token': None,
            'angel_obj': None, 'angel_jwt': None, 'angel_refresh_token': None,
            'selected_broker': 'fyers' # Default broker
        }
    return user_sessions[username]

# ---- Angel One Helper Functions ----
def load_angel_master():
    """Download Angel One instrument master file"""
    global angel_instruments_df
    try:
        url = "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json"
        response = requests.get(url, timeout=10)
        data = response.json()
        df = pd.DataFrame(data)
        df.columns = df.columns.str.strip().str.lower()
        str_cols = df.select_dtypes(include='object').columns
        df[str_cols] = df[str_cols].apply(lambda col: col.str.strip())
        angel_instruments_df = df
        print("✅ Angel Master File Downloaded")
    except Exception as e:
        print(f"❌ Failed to download Angel Master: {e}")

def get_angel_token(trading_symbol):
    """Find Angel token and symbol format for a given trading symbol (e.g., NIFTY25APR22000CE)"""
    global angel_instruments_df
    if angel_instruments_df is None: load_angel_master()
    
    try:
        # Angel Symbol Format usually: NIFTY25APR22000CE (No exchange prefix)
        # Input from Fyers: NSE:NIFTY25APR22000CE
        sym = trading_symbol.split(":")[-1] if ":" in trading_symbol else trading_symbol
        
        match = angel_instruments_df[
            (angel_instruments_df['symbol'] == 'NIFTY') & 
            (angel_instruments_df['name'] == sym) # 'name' column in Angel master usually holds the trading symbol
        ]
        
        if not match.empty:
            token = match.iloc[0]['token']
            exch_sym = match.iloc[0]['symbol'] # Just 'NIFTY'
            # Reconstruct correct angel tradingsymbol
            return str(token), sym
        return None, None
    except Exception as e:
        print(f"Error finding Angel Token: {e}")
        return None, None

def login_angel(username):
    """Login to Angel One and store session"""
    user_sess = get_user_session(username)
    creds = get_user_credentials(username)
    
    if not creds or not creds.get('angel_api_key'):
        return False, "Angel API Key missing"

    try:
        smartApi = SmartConnect(creds['angel_api_key'])
        totp = pyotp.TOTP(creds['angel_totp']).now()
        
        data = smartApi.generateSession(creds['angel_client_code'], creds['angel_pin'], totp)
        
        if data.get('status'):
            user_sess['angel_obj'] = smartApi
            user_sess['angel_jwt'] = data['data']['jwtToken']
            user_sess['angel_refresh_token'] = data['data']['refreshToken']
            print(f"✅ Angel One Login Successful for {username}")
            return True, "Success"
        else:
            msg = data.get('message', 'Unknown Error')
            print(f"❌ Angel Login Failed: {msg}")
            return False, msg
    except Exception as e:
        print(f"❌ Angel Exception: {e}")
        return False, str(e)

# ---- Initialization ----
load_angel_master() # Load Angel Master on startup

# ---- Fyers Functions ----
def init_fyers_for_user(username, client_id, secret_key, auth_code):
    user_sess = get_user_session(username)
    try:
        appSession = fyersModel.SessionModel(
            client_id=client_id, secret_key=secret_key, redirect_uri=user_sess['redirect_uri'],
            response_type="code", grant_type="authorization_code", state="sample"
        )
        appSession.set_token(auth_code)
        token_response = appSession.generate_token()
        access_token = token_response.get("access_token")
        if not access_token: return False

        user_sess['fyers'] = fyersModel.FyersModel(client_id=client_id, token=access_token, is_async=False, log_path="")
        return True
    except Exception as e:
        print(f"❌ Fyers Init Error: {e}")
        return False

def set_atm_strike(username):
    user_sess = get_user_session(username)
    if user_sess['fyers'] is None: return False
    try:
        data = {"symbol": user_sess['selected_index'], "strikecount": 20, "timestamp": ""}
        response = user_sess['fyers'].optionchain(data=data)
        if "data" not in response: return False
        
        options_data = response["data"]["optionsChain"]
        df = pd.DataFrame(options_data)
        nifty_spot = response["data"].get("underlyingValue", None)
        if nifty_spot is None: nifty_spot = df["strike_price"].iloc[len(df) // 2]
        
        user_sess['atm_strike'] = min(df["strike_price"], key=lambda x: abs(x - nifty_spot))
        
        df_pivot = df.pivot_table(index="strike_price", columns="option_type", 
                                  values=["ltp", "ltpch", "oich", "volume", "oi"], aggfunc="first").reset_index()
        df_pivot.columns = [f"{col[0]}_{col[1]}" if col[1] else col[0] for col in df_pivot.columns]
        df_pivot = df_pivot.rename(columns={"ltp_CE": "CE_LTP", "ltp_PE": "PE_LTP", "ltpch_CE": "CE_Chng", "ltpch_PE": "PE_Chng",
                                            "oich_CE": "CE_OI_Chng", "oich_PE": "PE_OI_Chng", "volume_CE": "CE_VOLUME", 
                                            "volume_PE": "PE_VOLUME", "oi_CE": "CE_OI", "oi_PE": "PE_OI"})
        
        user_sess['initial_data'] = df_pivot.to_dict(orient="records")
        user_sess['signals'].clear()
        user_sess['placed_orders'].clear()
        return True
    except Exception as e:
        print(f"❌ ATM Error: {e}")
        return False

# ---- Broker Order Placement ----
def place_fyers_order(username, symbol, price, side):
    user_sess = get_user_session(username)
    try:
        data = {
            "symbol": symbol, "qty": user_sess['quantity'], "type": 1, "side": side,
            "productType": "INTRADAY", "limitPrice": price, "stopPrice": 0,
            "validity": "DAY", "disclosedQty": 0, "offlineOrder": False, "orderTag": "signalorder"
        }
        return user_sess['fyers'].place_order(data=data)
    except Exception as e:
        return {"status": "error", "message": str(e)}

def place_mstock_order(username, symbol, price, side):
    user_sess = get_user_session(username)
    creds = get_user_credentials(username)
    token = user_sess.get('mstock_access_token')
    if not token: return {"status": "error", "message": "mStock not authenticated"}

    try:
        mstock_sym = symbol.split(":")[-1] if ":" in symbol else symbol
        trans_type = "BUY" if side == 1 else "SELL"
        headers = {
            'X-Mirae-Version': '1', 'Authorization': f'token {creds["mstock_api_key"]}:{token}',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        data = {
            'tradingsymbol': mstock_sym, 'exchange': 'NFO', 'transaction_type': trans_type,
            'order_type': "LIMIT" if price > 0 else "MARKET", 'quantity': user_sess['quantity'],
            'product': 'MIS', 'validity': 'DAY', 'price': price, 'variety': 'regular'
        }
        resp = requests.post('https://api.mstock.trade/openapi/typea/orders/regular', headers=headers, data=data)
        return resp.json()
    except Exception as e:
        return {"status": "error", "message": str(e)}

def place_angel_order(username, symbol, price, side):
    user_sess = get_user_session(username)
    if not user_sess.get('angel_obj'):
        success, _ = login_angel(username)
        if not success: return {"status": "error", "message": "Angel One login failed"}

    try:
        # Convert Fyers Symbol to Angel Token
        # Fyers: NSE:NIFTY25JAN22000CE -> Angel Token lookup
        token, angel_sym = get_angel_token(symbol)
        if not token: return {"status": "error", "message": "Symbol token not found in Angel Master"}

        trans_type = "BUY" if side == 1 else "SELL"
        
        order_params = {
            "variety": "NORMAL",
            "tradingsymbol": angel_sym,
            "symboltoken": token,
            "transactiontype": trans_type,
            "exchange": "NFO",
            "ordertype": "MARKET", # Using Market for simplicity, can use LIMIT
            "producttype": "INTRADAY",
            "duration": "DAY",
            "price": "0", # 0 for market
            "quantity": str(user_sess['quantity'])
        }
        
        resp = user_sess['angel_obj'].placeOrder(order_params)
        return resp
    except Exception as e:
        return {"status": False, "message": str(e)}

def place_order(username, symbol, price, side):
    user_sess = get_user_session(username)
    broker = user_sess.get('selected_broker', 'fyers')
    
    print(f"📤 Placing Order on {broker.upper()}: {symbol}")
    
    if broker == 'fyers':
        return place_fyers_order(username, symbol, price, side)
    elif broker == 'mstock':
        return place_mstock_order(username, symbol, price, side)
    elif broker == 'angel':
        return place_angel_order(username, symbol, price, side)
    else:
        return {"status": "error", "message": "Invalid Broker Selected"}

# ---- Background Bot Logic ----
def process_option_chain(username, df_pivot, response):
    user_sess = get_user_session(username)
    if user_sess['atm_strike'] is None: return

    ce_target = user_sess['atm_strike'] + user_sess['ce_offset']
    pe_target = user_sess['atm_strike'] + user_sess['pe_offset']

    for row in df_pivot.itertuples():
        strike = row.strike_price
        ce_ltp = getattr(row, "CE_LTP", None)
        pe_ltp = getattr(row, "PE_LTP", None)

        if strike == ce_target and ce_ltp:
            initial = next((i["CE_LTP"] for i in user_sess['initial_data'] if i["strike_price"] == strike), None)
            if initial and ce_ltp > initial + user_sess['atm_ce_plus20']:
                sig = f"CE_OFFSET_{strike}"
                if sig not in user_sess['placed_orders']:
                    user_sess['signals'].append(f"{strike} CE Signal @ {ce_ltp}")
                    place_order(username, f"{user_sess['symbol_prefix']}{strike}CE", ce_ltp, 1)
                    user_sess['placed_orders'].add(sig)

        if strike == pe_target and pe_ltp:
            initial = next((i["PE_LTP"] for i in user_sess['initial_data'] if i["strike_price"] == strike), None)
            if initial and pe_ltp > initial + user_sess['atm_pe_plus20']:
                sig = f"PE_OFFSET_{strike}"
                if sig not in user_sess['placed_orders']:
                    user_sess['signals'].append(f"{strike} PE Signal @ {pe_ltp}")
                    place_order(username, f"{user_sess['symbol_prefix']}{strike}PE", pe_ltp, 1)
                    user_sess['placed_orders'].add(sig)

def background_bot_worker(username):
    user_sess = get_user_session(username)
    print(f"🤖 Bot Started for {username} using {user_sess['selected_broker']}")
    while user_sess['bot_running']:
        if user_sess['fyers'] is None: time.sleep(5); continue
        try:
            data = {"symbol": user_sess['selected_index'], "strikecount": 20, "timestamp": ""}
            resp = user_sess['fyers'].optionchain(data=data)
            if "data" in resp and "optionsChain" in resp["data"]:
                df = pd.DataFrame(resp["data"]["optionsChain"])
                df_pivot = df.pivot_table(index="strike_price", columns="option_type", 
                                          values=["ltp", "ltpch", "oich", "volume", "oi"], aggfunc="first").reset_index()
                df_pivot.columns = [f"{c[0]}_{c[1]}" if c[1] else c[0] for c in df_pivot.columns]
                df_pivot = df_pivot.rename(columns={"ltp_CE":"CE_LTP", "ltp_PE":"PE_LTP", "ltpch_CE":"CE_Chng", "ltpch_PE":"PE_Chng",
                                                    "oich_CE":"CE_OI_Chng", "oich_PE":"PE_OI_Chng", "volume_CE":"CE_VOLUME", 
                                                    "volume_PE":"PE_VOLUME", "oi_CE":"CE_OI", "oi_PE":"PE_OI"})
                process_option_chain(username, df_pivot, resp)
        except Exception as e: print(f"Bot Error: {e}")
        time.sleep(2)

# ---- Routes ----
@app.route('/sp', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        u, p, e = request.form.get('username'), request.form.get('password'), request.form.get('email')
        if get_user(u): return render_template_string(SIGNUP_TEMPLATE, error="User exists!")
        save_user(u, p, e)
        return redirect(url_for('login_page'))
    return render_template_string(SIGNUP_TEMPLATE)

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        u, p = request.form.get('username'), request.form.get('password')
        user = verify_user(u, p)
        if user:
            session['username'] = user['username']
            creds = get_user_credentials(u)
            if creds and creds.get('client_id') and creds.get('secret_key') and creds.get('auth_code'):
                if init_fyers_for_user(u, creds['client_id'], creds['secret_key'], creds['auth_code']):
                    set_atm_strike(u)
            return redirect(url_for('index'))
        return render_template_string(LOGIN_TEMPLATE, error="Invalid!")
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    username = session['username']
    user_sess = get_user_session(username)
    
    if request.method == "POST":
        user_sess['atm_ce_plus20'] = float(request.form.get("atm_ce_plus20", 20))
        user_sess['atm_pe_plus20'] = float(request.form.get("atm_pe_plus20", 20))
        user_sess['quantity'] = int(request.form.get("quantity", 75))
        user_sess['ce_offset'] = int(request.form.get("ce_offset", -300))
        user_sess['pe_offset'] = int(request.form.get("pe_offset", 300))
        user_sess['selected_broker'] = request.form.get("selected_broker", "fyers")
        prefix = request.form.get("symbol_prefix")
        if prefix: user_sess['symbol_prefix'] = prefix.strip()

    if user_sess['fyers'] and user_sess['atm_strike'] is None: set_atm_strike(username)
    
    return render_template_string(MAIN_TEMPLATE, sess=user_sess, username=username)

@app.route("/setup_credentials", methods=["GET", "POST"])
@login_required
def setup_credentials():
    username = session['username']
    creds = get_user_credentials(username) or {}
    if request.method == "POST":
        save_user_credentials(username, 
                              client_id=request.form.get("client_id"),
                              secret_key=request.form.get("secret_key"),
                              mstock_api_key=request.form.get("mstock_api_key"),
                              angel_api_key=request.form.get("angel_api_key"),
                              angel_client_code=request.form.get("angel_client_code"),
                              angel_pin=request.form.get("angel_pin"),
                              angel_totp=request.form.get("angel_totp"))
        return redirect(url_for('fyers_login'))
    return render_template_string(CREDENTIALS_TEMPLATE, creds=creds)

@app.route("/fyers_login")
@login_required
def fyers_login():
    username = session['username']
    creds = get_user_credentials(username)
    user_sess = get_user_session(username)
    if not creds or not creds['client_id']: return redirect(url_for('setup_credentials'))
    
    appSession = fyersModel.SessionModel(client_id=creds['client_id'], secret_key=creds['secret_key'],
                                         redirect_uri=user_sess['redirect_uri'], response_type="code", 
                                         grant_type="authorization_code", state="sample")
    return redirect(appSession.generate_authcode())

@app.route("/callback/<username>")
def callback(username):
    auth_code = request.args.get("auth_code")
    if auth_code:
        creds = get_user_credentials(username)
        if creds:
            save_user_credentials(username, auth_code=auth_code)
            if init_fyers_for_user(username, creds['client_id'], creds['secret_key'], auth_code):
                set_atm_strike(username)
                return "<h2>✅ Fyers Auth Done!</h2>"
    return "❌ Auth failed."

@app.route("/fetch")
@login_required
def fetch_option_chain():
    username = session['username']
    user_sess = get_user_session(username)
    if user_sess['fyers'] is None: return jsonify({"error": "Login Fyers first"})
    try:
        data = {"symbol": user_sess['selected_index'], "strikecount": 20, "timestamp": ""}
        resp = user_sess['fyers'].optionchain(data=data)
        if "data" not in resp: return jsonify({"error": "API Error"})
        
        df = pd.DataFrame(resp["data"]["optionsChain"])
        df_pivot = df.pivot_table(index="strike_price", columns="option_type", 
                                  values=["ltp", "ltpch", "oich", "volume", "oi"], aggfunc="first").reset_index()
        df_pivot.columns = [f"{c[0]}_{c[1]}" if c[1] else c[0] for c in df_pivot.columns]
        df_pivot = df_pivot.rename(columns={"ltp_CE":"CE_LTP", "ltp_PE":"PE_LTP", "ltpch_CE":"CE_Chng", "ltpch_PE":"PE_Chng",
                                            "oich_CE":"CE_OI_Chng", "oich_PE":"PE_OI_Chng", "volume_CE":"CE_VOLUME", 
                                            "volume_PE":"PE_VOLUME", "oi_CE":"CE_OI", "oi_PE":"PE_OI"})
        
        process_option_chain(username, df_pivot, resp)
        res = json.loads(df_pivot.to_json(orient="records"))
        res.append({"atm_strike": user_sess['atm_strike']})
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/mstock/login", methods=["POST"])
@login_required
def login_mstock():
    username = session['username']
    user_sess = get_user_session(username)
    creds = get_user_credentials(username)
    totp = request.json.get("totp")
    if not creds or not creds['mstock_api_key']: return jsonify({"status":"error", "msg":"Config missing"})
    
    checksum = hashlib.sha256(f"{creds['mstock_api_key']}{totp}{MSTOCK_API_SECRET}".encode()).hexdigest()
    data = {'api_key': creds['mstock_api_key'], 'totp': totp, 'checksum': checksum}
    try:
        r = requests.post('https://api.mstock.trade/openapi/typea/session/verifytotp', 
                          headers={'X-Mirae-Version': '1'}, data=data)
        d = r.json()
        if d.get("status") == "success":
            user_sess['mstock_access_token'] = d["data"]["access_token"]
            return jsonify({"status": "success", "token": user_sess['mstock_access_token']})
        return jsonify({"status": "error", "msg": d.get("message")})
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)})

@app.route("/angel/login", methods=["POST"])
@login_required
def login_angel_route():
    username = session['username']
    success, msg = login_angel(username)
    if success: return jsonify({"status": "success"})
    return jsonify({"status": "error", "msg": msg})

@app.route("/start_bot", methods=["POST"])
@login_required
def start_bot():
    username = session['username']
    user_sess = get_user_session(username)
    if user_sess['fyers'] is None: return jsonify({"error": "Login Fyers first"})
    user_sess['bot_running'] = True
    threading.Thread(target=background_bot_worker, args=(username,), daemon=True).start()
    return jsonify({"message": f"Bot started on {user_sess['selected_broker']}"})

@app.route("/stop_bot", methods=["POST"])
@login_required
def stop_bot():
    get_user_session(session['username'])['bot_running'] = False
    return jsonify({"message": "Bot stopped"})

# ---- Templates ----
SIGNUP_TEMPLATE = """<!DOCTYPE html><html><head><title>Sign Up</title><style>body{font-family:Arial;background:#667eea;display:flex;justify-content:center;align-items:center;height:100vh}.box{background:#fff;padding:40px;border-radius:10px;box-shadow:0 10px 25px rgba(0,0,0,0.2);width:350px}h2{text-align:center;margin-bottom:20px}input{width:100%;padding:10px;margin:10px 0;border:1px solid #ddd;border-radius:5px}button{width:100%;padding:10px;background:#667eea;color:#fff;border:none;border-radius:5px;cursor:pointer}.error{color:red;text-align:center}</style></head><body><div class="box"><h2>📝 Sign Up</h2>{% if error %}<div class="error">{{error}}</div>{% endif %}<form method="POST"><input type="text" name="username" placeholder="Username" required><input type="email" name="email" placeholder="Email" required><input type="password" name="password" placeholder="Password" required><button>Sign Up</button></form><p style="text-align:center;margin-top:15px"><a href="/login">Login</a></p></div></body></html>"""

LOGIN_TEMPLATE = """<!DOCTYPE html><html><head><title>Login</title><style>body{font-family:Arial;background:#667eea;display:flex;justify-content:center;align-items:center;height:100vh}.box{background:#fff;padding:40px;border-radius:10px;box-shadow:0 10px 25px rgba(0,0,0,0.2);width:350px}h2{text-align:center;margin-bottom:20px}input{width:100%;padding:10px;margin:10px 0;border:1px solid #ddd;border-radius:5px}button{width:100%;padding:10px;background:#667eea;color:#fff;border:none;border-radius:5px;cursor:pointer}.error{color:red;text-align:center}</style></head><body><div class="box"><h2>🔐 Login</h2>{% if error %}<div class="error">{{error}}</div>{% endif %}<form method="POST"><input type="text" name="username" placeholder="Username" required><input type="password" name="password" placeholder="Password" required><button>Login</button></form><p style="text-align:center;margin-top:15px"><a href="/sp">Sign Up</a></p></div></body></html>"""

CREDENTIALS_TEMPLATE = """<!DOCTYPE html><html><head><title>Setup</title><style>body{font-family:Arial;background:#f4f4f9;padding:20px}.container{max-width:800px;margin:auto;background:#fff;padding:30px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1)}h2{text-align:center;color:#333}h3{border-bottom:2px solid #667eea;padding-bottom:5px;margin-top:20px}.form-group{margin-bottom:15px}.form-group label{display:block;font-weight:bold;margin-bottom:5px}.form-group input{width:100%;padding:10px;border:1px solid #ddd;border-radius:5px}button{width:100%;padding:12px;background:#667eea;color:#fff;border:none;border-radius:5px;cursor:pointer;font-size:16px}</style></head><body><div class="container"><h2>🔑 API Configuration</h2><form method="POST"><h3>Fyers (Data & Trading)</h3><div class="form-group"><label>Client ID</label><input type="text" name="client_id" value="{{ creds.client_id or '' }}"></div><div class="form-group"><label>Secret Key</label><input type="text" name="secret_key" value="{{ creds.secret_key or '' }}"></div><h3>mStock (Trading)</h3><div class="form-group"><label>mStock API Key</label><input type="text" name="mstock_api_key" value="{{ creds.mstock_api_key or '' }}"></div><h3>Angel One (Trading)</h3><div class="form-group"><label>Angel API Key</label><input type="text" name="angel_api_key" value="{{ creds.angel_api_key or '' }}"></div><div class="form-group"><label>Client Code</label><input type="text" name="angel_client_code" value="{{ creds.angel_client_code or '' }}"></div><div class="form-group"><label>PIN</label><input type="text" name="angel_pin" value="{{ creds.angel_pin or '' }}"></div><div class="form-group"><label>TOTP Secret (Base32)</label><input type="text" name="angel_totp" value="{{ creds.angel_totp or '' }}" placeholder="Enter TOTP Secret from Authenticator App"></div><button>Save & Connect</button></form></div></body></html>"""

MAIN_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>Algo Bot</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; }
        .header { background: #fff; padding: 15px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); display: flex; justify-content: space-between; align-items: center; }
        .header h1 { font-size: 20px; color: #333; }
        .nav a { margin-left: 15px; text-decoration: none; color: #667eea; font-weight: bold; }
        .container { max-width: 1400px; margin: 20px auto; padding: 0 20px; }
        .card { background: #fff; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }
        .grid { display: grid; grid-template-columns: 300px 1fr; gap: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: 600; color: #555; }
        input, select { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        button { padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; margin-right: 5px; }
        .btn-primary { background: #667eea; color: #fff; }
        .btn-success { background: #28a745; color: #fff; }
        .btn-danger { background: #dc3545; color: #fff; }
        .btn-warning { background: #ffc107; color: #000; }
        table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 10px; }
        th, td { padding: 8px; text-align: center; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; }
        .atm-row { background: #e3f2fd !important; font-weight: bold; }
        .signal-box { background: #f8f9fa; padding: 10px; border-radius: 4px; max-height: 150px; overflow-y: auto; }
        .status-bar { margin-top: 10px; padding: 10px; background: #e9ecef; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 Multi-Broker Algo (Fyers | mStock | Angel)</h1>
        <div class="nav">
            <span>{{ username }}</span>
            <a href="/setup_credentials">Settings</a>
            <a href="/logout">Logout</a>
        </div>
    </div>

    <div class="container">
        <div class="grid">
            <!-- Config Panel -->
            <div class="card">
                <h3>⚙️ Configuration</h3>
                <form method="POST">
                    <div class="form-group">
                        <label>Execution Broker</label>
                        <select name="selected_broker">
                            <option value="fyers" {% if sess.selected_broker == 'fyers' %}selected{% endif %}>Fyers</option>
                            <option value="mstock" {% if sess.selected_broker == 'mstock' %}selected{% endif %}>mStock</option>
                            <option value="angel" {% if sess.selected_broker == 'angel' %}selected{% endif %}>Angel One</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Quantity</label>
                        <input type="number" name="quantity" value="{{ sess.quantity }}">
                    </div>
                    <div class="form-group">
                        <label>CE Offset</label>
                        <input type="number" name="ce_offset" value="{{ sess.ce_offset }}">
                    </div>
                    <div class="form-group">
                        <label>PE Offset</label>
                        <input type="number" name="pe_offset" value="{{ sess.pe_offset }}">
                    </div>
                    <div class="form-group">
                        <label>Symbol Prefix (Fyers Format)</label>
                        <input type="text" name="symbol_prefix" value="{{ sess.symbol_prefix }}">
                    </div>
                    <button class="btn-primary" style="width:100%">Save Config</button>
                </form>
                
                <div style="margin-top:20px">
                    <button class="btn-success" onclick="startBot()">Start Bot</button>
                    <button class="btn-danger" onclick="stopBot()">Stop Bot</button>
                </div>

                <div class="status-bar">
                    <small>
                        Fyers: <span id="fyers_status">{% if sess.fyers %}✅{% else %}❌{% endif %}</span><br>
                        mStock: <span id="mstock_status">{% if sess.mstock_access_token %}✅{% else %}❌{% endif %}</span><br>
                        Angel: <span id="angel_status">{% if sess.angel_obj %}✅{% else %}❌{% endif %}</span>
                    </small>
                    <div style="margin-top:5px;">
                        <button class="btn-warning" style="font-size:10px" onclick="loginMstock()">Login mStock</button>
                        <button class="btn-warning" style="font-size:10px" onclick="loginAngel()">Login Angel</button>
                    </div>
                </div>

                <div class="signal-box" style="margin-top:20px">
                    <h4>Signals</h4>
                    <div id="signals"></div>
                </div>
            </div>

            <!-- Data Panel -->
            <div class="card">
                <h3>📊 Option Chain (Fyers Data) | Executing on: <span style="color:#667eea">{{ sess.selected_broker }}</span></h3>
                <div id="chain">Loading...</div>
            </div>
        </div>
    </div>

    <script>
        // Broker Logins
        async function loginMstock(){
            let otp = prompt("Enter mStock OTP:");
            if(!otp) return;
            let res = await fetch('/mstock/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({totp: otp})
            });
            let data = await res.json();
            if(data.status === 'success') {
                document.getElementById('mstock_status').innerText = '✅';
                alert('mStock Connected!');
            } else alert('Error: ' + data.msg);
        }

        async function loginAngel(){
            let res = await fetch('/angel/login', {method: 'POST'});
            let data = await res.json();
            if(data.status === 'success') {
                document.getElementById('angel_status').innerText = '✅';
                alert('Angel One Connected!');
            } else alert('Error: ' + data.msg);
        }

        // Bot Controls
        async function startBot(){
            let res = await fetch('/start_bot', {method: 'POST'});
            alert((await res.json()).message);
        }
        async function stopBot(){
            let res = await fetch('/stop_bot', {method: 'POST'});
            alert((await res.json()).message);
        }

        // Data Fetcher
        async function fetchChain(){
            try {
                let res = await fetch('/fetch');
                let data = await res.json();
                if(data.error) {
                    document.getElementById('chain').innerText = data.error;
                    return;
                }
                
                let atm = data.pop().atm_strike;
                let html = `<table><thead><tr><th>Strike</th><th>CE LTP</th><th>PE LTP</th><th>Signal</th></tr></thead><tbody>`;
                
                data.forEach(r => {
                    let isAtm = (r.strike_price === atm);
                    html += `<tr class="${isAtm ? 'atm-row' : ''}">
                        <td>${r.strike_price}</td>
                        <td style="color:green">${r.CE_LTP || '-'}</td>
                        <td style="color:red">${r.PE_LTP || '-'}</td>
                        <td>${r.CE_LTP > 20 ? '🔺' : ''} ${r.PE_LTP > 20 ? '🔻' : ''}</td>
                    </tr>`;
                });
                html += '</tbody></table>';
                document.getElementById('chain').innerHTML = html;
            } catch(e) { console.error(e); }
        }

        // Signals Fetcher
        async function fetchSignals(){
            let res = await fetch('/bot_status');
            let data = await res.json();
            document.getElementById('signals').innerHTML = data.signals.map(s => `<div>• ${s}</div>`).join('');
        }

        setInterval(fetchChain, 3000);
        setInterval(fetchSignals, 2000);
        fetchChain();
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    print("🚀 Multi-Broker Algo Started")
    app.run(host="0.0.0.0", port=5000, debug=False)
