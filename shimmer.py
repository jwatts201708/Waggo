#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PROJECT SHIMMER: Unified & Secure Ecosystem (Formerly Project Hydra)
==================================================================
This script represents the final, complete, and unified version of the application.
It integrates all features, data registries, modular services, and web pages
into a single, self-contained, and deployable Flask application.
"""

import os
import io
import sys
import json
import logging
import secrets
import random
import time
import hashlib
import binascii
from datetime import datetime
from functools import wraps
from typing import Dict, Any, List, Optional, Tuple

# Flask & Extensions
from flask import (
    Flask, jsonify, request, send_file, render_template_string,
    redirect, url_for, flash, abort, make_response
)
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user, login_required, current_user
)
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import JSON as SA_JSON
from sqlalchemy import ForeignKey
from sqlalchemy.orm.attributes import flag_modified

# Crypto & Web3
import requests
from hdwallet import HDWallet
from hdwallet.symbols import BTC, ETH, LTC, DOGE, SOL
from PIL import Image, ImageDraw, ImageFilter
import numpy as np
import qrcode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

backend = default_backend()

# Load env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ==============================================================================
# 1. CONFIGURATION & DATA REGISTRIES
# ==============================================================================

class Config:
    """Main application configuration."""
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-shimmer-secret-key-01")
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "dl3gANDwq8eCsDisomWFLxYAnT-UD4S0X5uOMpEsLbY=") # Fallback for dev
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///shimmer_ecosystem.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    RATELIMIT_DEFAULT = "200 per day;50 per hour"
    RATELIMIT_STORAGE_URI = "memory://"

    # Core Identity
    MASTER_MNEMONIC = os.getenv("MASTER_MNEMONIC", "Bargain country rose minimum safe alter damage metal thumb radio relief glory")
    GENERATOR_SEED_HASH = "Edd57c86a3da6183ce37d18b443fd01b166ff12e8036028189e907a4b950bb9c"

    # Addresses
    PRIMARY_TREASURY_ADDRESS = "0xFC362d4dd54796eB0a5340949B579D673867D834"
    HARDWIRED_NFT_RECIPIENT_ADDRESS = "0xFC362d4dd54796eB0a5340949B579D673867D834"

# Hardwired Data Registry
WALLET_ANALYSIS_DATA = {
    "0xFC362d4dd54796eB0a5340949B579D673867D834": {
        "address": "0xFC362d4dd54796eB0a5340949B579D673867D834",
        "public_label": "Primary Shimmer Treasury Address",
        "network": "Ethereum",
        "relationships": {
             "funded_by": [
                 "bc1qaxagqdeuxqh58kjdmv8d4z8zqa48zqstd63tnr",
                 "bc1q0f5rc2krru05rlvtu68958fm89vrhvp5fftvs0"
             ]
        }
    },
    "0x71C7656EC7ab88b098defB751B7401B5f6d8976F": {
        "address": "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
        "network": "Ethereum",
        "public_label": "Vb 3 (External Key)",
        "inferred_identity": "Vitalik Buterin",
        "funded_by": "0xFC362d4dd54796eB0a5340949B579D673867D834"
    },
    "0x175BE7DOb8E3Eb9C379849770C379849770C": {
         "address": "0x175BE7DOb8E3Eb9C379849770C379849770C",
         "network": "Ethereum",
         "public_label": "Suspicious Wallet (Incident Analysis)",
         "notes": "Linked to Johnny watts / Ka tags. Suspicious transfer of 4,865.23 USDT."
    },
    "bc1q5dhcpfn4furw7ny0s5ch5wurp30zkjen2kw37r": {
        "address": "bc1q5dhcpfn4furw7ny0s5ch5wurp30zkjen2kw37r",
        "network": "Bitcoin",
        "public_label": "Primary BTC Address"
    }
}

LIQUID_NETWORK_DATA = {
    "addresses": {
        "lq1qqw4qflfq7wjddxtxxzcvvd829shyj2a53p0nc5dwfe77sgt7y87g02drgj8460duzwezm5cayc9sms2l3z5pcgj59lfpqallk": {
             "asset_id": "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d",
             "type": "liquid bitcoin"
        },
         "lq1qqggzdrv3jqlakctmczykkhx06uhxcx7hhm5d9rtp6dyt9mlyrvvkpm87mphpnsp3zm7wcutk23ms6x2za7fpw6ut57nh5w3ww": {
            "asset_id": "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d",
            "type": "liquid bitcoin"
        }
    }
}

ECOSYSTEM_DATA = {
    "FAUCETS": [
        {"name": "Base Sepolia Faucet by Alchemy", "url": "https://basefaucet.com/", "network": "Base Sepolia"},
        {"name": "Superchain Faucet", "url": "https://app.optimism.io/faucet", "network": "OP Chains"},
    ],
    "NODE_PROVIDERS": [
        {"name": "Alchemy", "url": "https://www.alchemy.com/", "networks": "Multi-chain"},
        {"name": "Coinbase Developer Platform", "url": "https://www.coinbase.com/cloud", "networks": "Base"},
    ]
}

# ==============================================================================
# 2. APPLICATION INITIALIZATION
# ==============================================================================

app = Flask(__name__)
app.config.from_object(Config)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('PROJECT_SHIMMER')

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(app, model_class=Base)
CORS(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login_page"
limiter = Limiter(get_remote_address, app=app, default_limits=[Config.RATELIMIT_DEFAULT], storage_uri=Config.RATELIMIT_STORAGE_URI)

# ==============================================================================
# 3. DATABASE MODELS
# ==============================================================================

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(db.Integer, primary_key=True)
    username: Mapped[str] = mapped_column(db.String(80), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(db.String(255), nullable=False)
    is_admin: Mapped[bool] = mapped_column(db.Boolean, default=False)
    portfolio: Mapped["EquityPortfolio"] = relationship(back_populates="user", uselist=False, cascade="all, delete-orphan")
    artworks: Mapped[List["GeneratedArt"]] = relationship(back_populates="user", cascade="all, delete-orphan")

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

class EquityPortfolio(db.Model):
    __tablename__ = 'equity_portfolios'
    id: Mapped[int] = mapped_column(db.Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), unique=True)
    holdings: Mapped[Dict[str, Any]] = mapped_column(SA_JSON, default=lambda: {})
    total_value_usd: Mapped[float] = mapped_column(db.Float, default=0.0)
    user: Mapped["User"] = relationship(back_populates="portfolio")

class GeneratedArt(db.Model):
    __tablename__ = 'generated_art'
    id: Mapped[int] = mapped_column(db.Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    seed_text: Mapped[str] = mapped_column(db.String(255))
    image_data: Mapped[bytes] = mapped_column(db.LargeBinary)
    created_at: Mapped[datetime] = mapped_column(db.DateTime, default=datetime.utcnow)
    user: Mapped["User"] = relationship(back_populates="artworks")

class GiftBox(db.Model):
    __tablename__ = "gift_boxes"
    id: Mapped[int] = mapped_column(db.Integer, primary_key=True)
    public_address: Mapped[str] = mapped_column(db.String(128), unique=True, nullable=False)
    encrypted_private_key: Mapped[Optional[str]] = mapped_column(db.Text, nullable=True)
    balance_satoshi: Mapped[int] = mapped_column(db.BigInteger, default=0)
    is_opened: Mapped[bool] = mapped_column(db.Boolean, default=False)
    recipient_address: Mapped[Optional[str]] = mapped_column(db.String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(db.DateTime, default=datetime.utcnow)

# ==============================================================================
# 4. SERVICES
# ==============================================================================

class CryptoUtils:
    @staticmethod
    def encrypt_aes_gcm(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext, nonce, encryptor.tag

    @staticmethod
    def decrypt_aes_gcm(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=backend)
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

class KeyService:
    def __init__(self):
        # In prod this should be a proper 32-byte key from env, strictly handled.
        # For this script we use the config key directly, padding if needed (unlikely if set correctly)
        raw_key = Config.ENCRYPTION_KEY
        if len(raw_key) > 32:
             # Just a simple check, in real app we decode base64 usually
             self.master_key = raw_key[:32].encode('utf-8')
        else:
             self.master_key = raw_key.ljust(32, '0').encode('utf-8')

    def encrypt_data(self, plaintext: str) -> str:
        pt_bytes = plaintext.encode('utf-8')
        ct, nonce, tag = CryptoUtils.encrypt_aes_gcm(pt_bytes, self.master_key)
        # Store as hex: nonce + tag + ciphertext
        return binascii.hexlify(nonce + tag + ct).decode('utf-8')

    def decrypt_data(self, encrypted_hex: str) -> str:
        data = binascii.unhexlify(encrypted_hex)
        nonce = data[:12]
        tag = data[12:28]
        ct = data[28:]
        pt_bytes = CryptoUtils.decrypt_aes_gcm(ct, self.master_key, nonce, tag)
        return pt_bytes.decode('utf-8')

class HDWalletService:
    SUPPORTED_SYMBOLS = {"BTC": BTC, "ETH": ETH, "LTC": LTC, "DOGE": DOGE, "SOL": SOL}

    def __init__(self, mnemonic):
        self.mnemonic = mnemonic

    def derive_wallet(self, coin, user_id):
        symbol = self.SUPPORTED_SYMBOLS.get(coin.upper(), ETH)
        # BIP44 path: m/44'/coin_type'/0'/0/index
        path = f"m/44'/{symbol.COIN_TYPE}'/0'/0/{user_id}"
        try:
            hdwallet = HDWallet(symbol=symbol, mnemonic=self.mnemonic)
            hdwallet.from_path(path)
            return hdwallet.dumps()
        except Exception as e:
            logger.error(f"Wallet derivation failed: {e}")
            return {}

class ArtGeneratorService:
    @staticmethod
    def generate_art_from_keywords(keywords: List[str], seed_hash: str, qr_payload: str) -> io.BytesIO:
        # Simulate art generation
        seed_val = int(hashlib.sha256(seed_hash.encode('utf-8')).hexdigest(), 16) % (2**32)
        np.random.seed(seed_val)
        random.seed(seed_val)

        width, height = 512, 512
        img = Image.new('RGB', (width, height), color=(255, 255, 255))
        draw = ImageDraw.Draw(img)

        # Draw some random rectangles based on keywords
        for _ in range(20):
            x1 = random.randint(0, width)
            y1 = random.randint(0, height)
            x2 = random.randint(0, width)
            y2 = random.randint(0, height)
            color = (random.randint(0,255), random.randint(0,255), random.randint(0,255))
            draw.rectangle([x1, y1, x2, y2], fill=color, outline=None)

        img = img.filter(ImageFilter.GaussianBlur(radius=2))

        # QR Code overlay
        qr = qrcode.QRCode(version=1, box_size=5, border=2)
        qr.add_data(qr_payload)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white").convert('RGB')

        # Paste QR in bottom right
        img.paste(qr_img, (width - qr_img.size[0] - 10, height - qr_img.size[1] - 10))

        buf = io.BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        return buf

# ==============================================================================
# 5. FLASK ADMIN & VIEWS
# ==============================================================================

class AuthAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login_page'))

class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

admin = Admin(app, name='Shimmer Admin', index_view=AuthAdminIndexView(url='/admin'))
admin.add_view(SecureModelView(User, db.session))
admin.add_view(SecureModelView(GiftBox, db.session))
admin.add_view(SecureModelView(EquityPortfolio, db.session))

# ==============================================================================
# 6. ROUTES
# ==============================================================================

TEMPLATES = {
    "layout": """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>{{ title }} - Project Shimmer</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
            <a class="navbar-brand" href="/">Project Shimmer</a>
            <div class="collapse navbar-collapse">
                <ul class="navbar-nav mr-auto">
                    {% if current_user.is_authenticated %}
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('dashboard_page') }}">Dashboard</a></li>
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('gift_page') }}">Gift Boxes</a></li>
                    {% if current_user.is_admin %}
                    <li class="nav-item"><a class="nav-link" href="/admin">Admin</a></li>
                    {% endif %}
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('logout_page') }}">Logout</a></li>
                    {% else %}
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('login_page') }}">Login</a></li>
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('register_page') }}">Register</a></li>
                    {% endif %}
                </ul>
            </div>
        </nav>
        <div class="container">
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ category }}">{{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            {{ content|safe }}
        </div>
    </body>
    </html>
    """,
    "dashboard": """
    <h2>Command Center</h2>
    <div class="row">
        <div class="col-md-6">
            <div class="card mb-4">
                <div class="card-header">Identity & Wallet</div>
                <div class="card-body">
                    <p><strong>Username:</strong> {{ current_user.username }}</p>
                    <p><strong>Admin Status:</strong> {{ current_user.is_admin }}</p>
                    <hr>
                    <h5>Integrated Wallet (ETH)</h5>
                    <pre>{{ wallet_eth.address }}</pre>
                </div>
            </div>
        </div>
        <div class="col-md-6">
             <div class="card mb-4">
                <div class="card-header">Portfolio Overview</div>
                <div class="card-body">
                    <p><strong>Total Value:</strong> ${{ portfolio.total_value_usd }}</p>
                    <pre>{{ portfolio.holdings }}</pre>
                </div>
            </div>
        </div>
    </div>
    <div class="card">
        <div class="card-header">System Intel</div>
        <div class="card-body">
             <p>Known Funding Sources: {{ funded_by_count }}</p>
        </div>
    </div>
    """,
    "giftbox": """
    <h2>Secure Gift Box Terminal</h2>
    <div class="mb-4">
        <form action="{{ url_for('create_gift_api') }}" method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
            <button type="submit" class="btn btn-primary">Generate New Gift Box</button>
        </form>
    </div>
    <table class="table table-striped">
        <thead>
            <tr>
                <th>ID</th>
                <th>Address</th>
                <th>Balance (Sats)</th>
                <th>Status</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
            {% for box in gifts %}
            <tr>
                <td>{{ box.id }}</td>
                <td>{{ box.public_address }}</td>
                <td>{{ box.balance_satoshi }}</td>
                <td>
                    {% if box.is_opened %}
                    <span class="badge badge-success">OPENED</span>
                    {% else %}
                    <span class="badge badge-warning">LOCKED</span>
                    {% endif %}
                </td>
                <td>
                    <a href="{{ url_for('view_gift_image', gift_id=box.id) }}" target="_blank" class="btn btn-sm btn-info">View Art</a>
                    {% if not box.is_opened %}
                    <form action="{{ url_for('open_gift_api', gift_id=box.id) }}" method="post" style="display:inline;">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
                        <button type="submit" class="btn btn-sm btn-success">Unlock</button>
                    </form>
                    {% endif %}
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    """,
    "auth": """
    <div class="row justify-content-center">
        <div class="col-md-6">
            <div class="card">
                <div class="card-header">{{ title }}</div>
                <div class="card-body">
                    <form method="post">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
                        <div class="form-group">
                            <label>Username</label>
                            <input type="text" name="username" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label>Password</label>
                            <input type="password" name="password" class="form-control" required>
                        </div>
                        <button type="submit" class="btn btn-primary btn-block">{{ title }}</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
    """
}

def render_page(template_key, title, **kwargs):
    content = render_template_string(TEMPLATES.get(template_key, ""), **kwargs)
    return render_template_string(TEMPLATES["layout"], title=title, content=content)

@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard_page'))
    return redirect(url_for('login_page'))

@app.route("/dashboard")
@login_required
def dashboard_page():
    hd_service = HDWalletService(Config.MASTER_MNEMONIC)
    # Derive user specific wallet (using user.id)
    wallet_data = hd_service.derive_wallet("ETH", current_user.id)

    # Portfolio
    pf = current_user.portfolio
    if not pf:
        pf = EquityPortfolio(total_value_usd=0, holdings={})

    return render_page("dashboard", "Dashboard",
                       wallet_eth=wallet_data,
                       portfolio=pf,
                       funded_by_count=len(WALLET_ANALYSIS_DATA))

@app.route("/giftbox")
@login_required
def gift_page():
    gifts = GiftBox.query.all()
    return render_page("giftbox", "Gift Boxes", gifts=gifts)

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if current_user.is_authenticated: return redirect(url_for('dashboard_page'))
    if request.method == "POST":
        u = User.query.filter_by(username=request.form['username']).first()
        if u and u.check_password(request.form['password']):
            login_user(u)
            return redirect(url_for('dashboard_page'))
        flash("Invalid credentials", "danger")
    return render_page("auth", "Login")

@app.route("/register", methods=["GET", "POST"])
def register_page():
    if current_user.is_authenticated: return redirect(url_for('dashboard_page'))
    if request.method == "POST":
        if User.query.filter_by(username=request.form['username']).first():
            flash("User exists", "danger")
        else:
            u = User(username=request.form['username'], is_admin=False)
            u.set_password(request.form['password'])
            # Check if first user, make admin
            if User.query.count() == 0:
                u.is_admin = True

            # Seed Portfolio
            pf = EquityPortfolio(
                user=u,
                holdings={"BTC": 0.5, "ETH": 2.0},
                total_value_usd=5500.00
            )

            db.session.add(u)
            db.session.add(pf)
            db.session.commit()
            login_user(u)
            return redirect(url_for('dashboard_page'))
    return render_page("auth", "Register")

@app.route("/logout")
@login_required
def logout_page():
    logout_user()
    return redirect(url_for('login_page'))

# --- API Actions ---

@app.route("/api/gift/create", methods=["POST"])
@login_required
def create_gift_api():
    # Derive a new address for the gift box based on count
    count = GiftBox.query.count()
    hd = HDWalletService(Config.MASTER_MNEMONIC)
    # Use a different derivation path offset for gifts to avoid collision with users
    wallet = hd.derive_wallet("BTC", 5000 + count)

    box = GiftBox(
        public_address=wallet.get('addresses', {}).get('p2wpkh', 'unknown'),
        balance_satoshi=random.randint(5000, 20000),
        recipient_address=None
    )
    # Simulate saving private key
    ks = KeyService()
    wif = wallet.get('wif')
    if wif:
        box.encrypted_private_key = ks.encrypt_data(wif)

    db.session.add(box)
    db.session.commit()
    flash("New Gift Box Created.", "success")
    return redirect(url_for('gift_page'))

@app.route("/api/gift/open/<int:gift_id>", methods=["POST"])
@login_required
def open_gift_api(gift_id):
    box = db.session.get(GiftBox, gift_id)
    if not box: abort(404)
    if box.is_opened:
        flash("Already opened.", "warning")
        return redirect(url_for('gift_page'))

    box.is_opened = True
    # "Transfer" to treasury
    box.recipient_address = Config.PRIMARY_TREASURY_ADDRESS
    db.session.commit()
    flash(f"Gift opened! Funds swept to {Config.PRIMARY_TREASURY_ADDRESS}", "success")
    return redirect(url_for('gift_page'))

@app.route("/api/gift/image/<int:gift_id>")
def view_gift_image(gift_id):
    box = db.session.get(GiftBox, gift_id)
    if not box: abort(404)

    # Generate art
    keywords = ["shimmer", "gold", "future", "secure"]
    seed = Config.GENERATOR_SEED_HASH + str(box.id)
    qr_data = f"bitcoin:{box.public_address}?amount={box.balance_satoshi/100000000}"

    img_io = ArtGeneratorService.generate_art_from_keywords(keywords, seed, qr_data)
    return send_file(img_io, mimetype='image/png')

@app.route("/api/data/wallets")
@login_required
def api_wallets():
    return jsonify(WALLET_ANALYSIS_DATA)

# ==============================================================================
# MAIN
# ==============================================================================

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # Seed Admin if needed
        if not User.query.filter_by(username="admin").first():
            u = User(username="admin", is_admin=True)
            u.set_password("admin123")
            db.session.add(u)
            db.session.commit()
            logger.info("Admin user seeded.")

    print("--- Project Shimmer Online ---")
    app.run(host="0.0.0.0", port=5000, debug=False)
