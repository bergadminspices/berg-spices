from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
load_dotenv()
from flask import send_file
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from datetime import datetime
from pymongo import MongoClient
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import ast
import csv
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from flask import session, redirect, url_for
from reportlab.platypus import Paragraph, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from xhtml2pdf import pisa
from flask import make_response
import io
from reportlab.lib.units import cm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Table, TableStyle, Image, Spacer)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from itsdangerous import URLSafeTimedSerializer
from flask import current_app
import random
from datetime import timedelta
#import razorpay razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
import re
from flask_wtf.csrf import CSRFProtect

def format_dt(dt):
    if isinstance(dt, datetime):
        return dt.strftime("%Y-%m-%d %H:%M")
    return dt or "-"
# -------------------------
# Canonical Order Statuses
# -------------------------
ORDER_STATUSES = {
    "PLACED",
    "PREPARING",
    "PAYMENT_PENDING",
    "SHIPPED",
    "DELIVERED",
    "DELAYED",
    "CANCELLED",
    "REFUND_INITIATED",
    "REFUNDED"
}

# -------------------------
# App init
# -------------------------
app = Flask(__name__)
csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

if not os.environ.get("FLASK_SECRET"):
    raise RuntimeError("FLASK_SECRET not set")
app.secret_key = os.environ["FLASK_SECRET"]
  # change for production

app.config.update(
    SESSION_COOKIE_SECURE=True,      # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,    # JS can't access
    SESSION_COOKIE_SAMESITE="Lax"
)

# -------------------------
# Config (set these env vars in production)
# -------------------------
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@bergspices.com")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 465))  # 465 for SSL
SMTP_USER = os.environ.get("SMTP_USER", "your_email@gmail.com")
SMTP_PASS = os.environ.get("SMTP_PASS", "your_app_password")  # Use app password for Gmail

app.permanent_session_lifetime = timedelta(days=7)
# -------------------------
# MongoDB connection
# -------------------------

MONGO_URI = os.environ.get("MONGO_URI")

if not MONGO_URI:
    raise RuntimeError("MONGO_URI is not set")

client = MongoClient(MONGO_URI)
db = client['bergspices']

products_col = db['products']
orders_col = db['orders']
users_col = db['users']
messages_col = db['messages']  # will store contact inquiries and replies
# -------------------------
# MongoDB Indexes (run once)
# -------------------------
try:
    users_col.create_index("email", unique=True)
    users_col.create_index("phone", unique=True)
    orders_col.create_index("order_id", unique=True)
    messages_col.create_index("user_id")
except Exception as e:
    print("Index creation skipped:", e)

# -------------------------
# Helpers / Decorators
# -------------------------
def login_required(f):
    """Decorator to ensure a user is logged in."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please login to continue.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to ensure an admin is logged in (role == 'admin')."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Admin login required", "danger")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# -------------------------
# Utilities
# -------------------------
def normalize_order_status(status):
    """
    Converts legacy / invalid statuses into canonical ones.
    """
    legacy_map = {
        "Pending": "PLACED",
        "Packed": "PREPARING",
        "In Progress": "PREPARING",
        "Sent": "SHIPPED",
        "Shipped": "SHIPPED",
        "Delivered": "DELIVERED",
        "Cancelled": "CANCELLED",
        "Information Required": "PAYMENT_PENDING",
    }
    return legacy_map.get(status, status if status in ORDER_STATUSES else "PLACED")

    
def get_cart_count():
    return sum(item.get("quantity", 0) for item in session.get("cart", []))

def is_product_in_cart(product_id):
    cart = session.get("cart", [])
    for item in cart:
        if str(item.get("id")) == str(product_id):
            return True
    return False

def send_email(subject: str, body_text: str, recipient: str, html_body: str = None, sender: str = None):
    """
    Send an email using configured SMTP. Returns True/False.
    """
    sender_email = sender or SMTP_USER
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = recipient

    msg.attach(MIMEText(body_text, "plain"))
    if html_body:
        msg.attach(MIMEText(html_body, "html"))

    try:
        server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10)
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(sender_email, [recipient], msg.as_string())
        server.quit()
        return True
    except Exception as e:
        app.logger.error(f"Email sending failed: {e}")
        return False

def send_sms(phone_number, message):
    # For now, just print to console
    print(f"SMS to {phone_number}: {message}")
    return True

# -------------------------
# Load products.csv into MongoDB (one-time sync)
# -------------------------
def sync_products_from_csv():
    if not os.path.exists("products.csv"):
        print("products.csv not found")
        return

    csv_skus = set()  # 🔑 track all products in CSV

    with open("products.csv", newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
            sku = row.get("sku")
            if not sku:
                continue  # skip bad rows

            csv_skus.add(sku)

            # safely parse price_options
            try:
                price_options = ast.literal_eval(row.get("price_options", "[]"))
            except Exception:
                price_options = []

            product = {
                "sku": sku,
                "name": row.get("name"),
                "image": row.get("image"),
                "description": row.get("description"),
                "category": row.get("category"),
                "price_options": price_options,
                "updated_at": datetime.now()
            }

            # 🔁 UPDATE or INSERT
            products_col.update_one(
                {"sku": sku},
                {"$set": product},
                upsert=True
            )

    # 🗑️ DELETE products removed from CSV
    products_col.delete_many({
        "sku": {"$nin": list(csv_skus)}
    })

    print("✅ Products synced with CSV")


# Run sync on startup
# sync_products_from_csv()

# Admin-triggered manual sync
@app.route("/admin/sync-products")
@admin_required
def admin_sync_products():
    sync_products_from_csv()
    flash("Products synced from CSV!", "success")
    return redirect(url_for("admin_dashboard"))

# -------------------------
# Seed default admin (only if none exists)
# -------------------------
def seed_default_admin():
    if users_col.count_documents({"role": "admin"}) == 0:
        admin_email = os.environ.get("DEFAULT_ADMIN_EMAIL")
        admin_password = os.environ.get("DEFAULT_ADMIN_PASSWORD")

        if not admin_email or not admin_password:
            print("⚠️ Admin credentials not set. Skipping admin creation.")
            return

        users_col.insert_one({
            "name": "Site Admin",
            "email": admin_email,
            "phone": "",
            "password": generate_password_hash(admin_password),
            "role": "admin",
            "created_at": datetime.now()
        })


# -------------------------
# Pages
# -------------------------
@app.route("/")
def home():
    categories = products_col.distinct("category")
    data = {}
    for cat in categories:
        data[cat] = list(products_col.find({"category": cat}))
    return render_template("index.html", categories=data, cart_count=get_cart_count())

@app.route("/about")
def about():
    return render_template("about.html", cart_count=get_cart_count())

# -------------------------
# Contact (save + email admin)
# -------------------------
@app.route("/contact", methods=["GET", "POST"])
def contact():
    user_id = session.get("user_id")
    new_messages_count = 0

    # Count unread messages if logged in
    if user_id:
        try:
            new_messages_count = get_unread_messages_count(user_id)
        except Exception:
            new_messages_count = 0

    # -------------------------
    # POST → Save inquiry + email admin
    # -------------------------
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        message = request.form.get("message", "").strip()

        if not name or not email or not message:
            flash("All fields are required.", "danger")
            return redirect(url_for("contact"))

        inquiry = {
            "user_id": ObjectId(user_id) if user_id else None,
            "name": name,
            "email": email,
            "message": message,
            "created_at": datetime.now(),
            "replies": [],
            "status": "New",
            "read": False
        }

        messages_col.insert_one(inquiry)

        # Send admin notification email
        subject = f"New Contact Inquiry from {name}"
        body = f"New inquiry received.\nName: {name}\nEmail: {email}\nMessage:\n{message}"

        html = (
            f"<p>New inquiry received.</p>"
            f"<p>Name: {name}<br>Email: {email}</p>"
            f"<p>Message:<br>{message.replace(chr(10), '<br/>')}</p>"
        )

        send_email(subject, body, ADMIN_EMAIL, html_body=html)

        flash("Your message has been sent!", "success")
        return redirect(url_for("contact"))

    # -------------------------
    # GET → Show contact page
    # -------------------------
    return render_template(
        "contact.html",
        cart_count=get_cart_count(),
        new_messages_count=new_messages_count
    )

# -------------------------
# Product Detail
# -------------------------
@app.route("/product/<product_id>")
def product_detail(product_id):
    try:
        product = products_col.find_one({"_id": ObjectId(product_id)})
    except Exception:
        product = None
    if not product:
        flash("Product not found", "danger")
        return redirect(url_for("home"))

    product.setdefault("price_options", [])
    return render_template("product_detail.html",
                           product=product,
                           product_in_cart=is_product_in_cart(product_id),
                           cart_count=get_cart_count())

# -------------------------
# Shopping Cart (add/view/remove/bulk)
# -------------------------
@app.route("/add_to_cart/<product_id>", methods=["POST"])
def add_to_cart(product_id):
    try:
        product = products_col.find_one({"_id": ObjectId(product_id)})
    except Exception:
        product = None

    if not product:
        flash("Product not found", "danger")
        return redirect(url_for("home"))

    selected_option = request.form.get("packet_option")
    try:
        quantity = int(request.form.get("quantity", 1))
    except (ValueError, TypeError):
        quantity = 1

    if not selected_option:
        flash("Please select a packet size!", "danger")
        return redirect(url_for("product_detail", product_id=product_id))

    price = next((p.get("price") for p in product.get("price_options", []) if p.get("label") == selected_option), None)
    if price is None:
        flash("Invalid packet option!", "danger")
        return redirect(url_for("product_detail", product_id=product_id))

    cart = session.get("cart", [])
    for item in cart:
        if item.get("id") == str(product_id) and item.get("packet") == selected_option:
            item["quantity"] = item.get("quantity", 0) + quantity
            break
    else:
        cart.append({
            "id": str(product_id),
            "name": product.get("name"),
            "price": float(price),
            "packet": selected_option,
            "quantity": quantity,
            "image": product.get("image", "no_image.jpg")
        })
    session["cart"] = cart
    flash(f"{product.get('name')} ({selected_option}) x{quantity} added!", "success")
    return redirect(url_for("view_cart"))

@app.route("/cart")
def view_cart():
    cart = session.get("cart", [])
    for item in cart:
        item.setdefault("image", "no_image.jpg")
        item.setdefault("quantity", 1)
        item.setdefault("price", 0.0)
    total = sum(item["price"] * item["quantity"] for item in cart)
    return render_template("cart.html", cart=cart, total=total, cart_count=get_cart_count())

@app.route("/remove_from_cart/<product_id>", methods=["POST"])
def remove_from_cart(product_id):
    packet = request.form.get("packet")
    if packet:
        new_cart = [item for item in session.get("cart", []) if not (str(item.get("id")) == str(product_id) and item.get("packet") == packet)]
    else:
        # if packet not provided, remove items matching the id
        new_cart = [item for item in session.get("cart", []) if not (str(item.get("id")) == str(product_id))]
    session["cart"] = new_cart
    flash("Item removed", "success")
    return redirect(url_for("view_cart"))

@app.route("/bulk_remove", methods=["POST"])
def bulk_remove():
    selected_items = request.form.getlist("selected_items")
    if not selected_items:
        flash("No items selected.", "warning")
        return redirect(url_for("view_cart"))

    new_cart = []
    for item in session.get("cart", []):
        key = f"{item.get('id')}||{item.get('packet')}"
        if key not in selected_items:
            new_cart.append(item)

    session["cart"] = new_cart
    flash("Selected items removed.", "success")
    return redirect(url_for("view_cart"))

# -------------------------
# AJAX: update quantity (returns JSON)
# -------------------------
@csrf.exempt
@app.route("/update_quantity_ajax/<product_id>", methods=["POST"])
def update_quantity_ajax(product_id):
    packet = request.form.get("packet")
    action = request.form.get("action")
    new_qty = request.form.get("quantity")
    cart = session.get("cart", [])
    item = None

    # find matching item. if packet provided match both; otherwise match by id (first found)
    for it in cart:
        if str(it.get("id")) == product_id and (packet is None or it.get("packet") == packet):
            item = it
            if action == "increase":
                it["quantity"] = it.get("quantity", 0) + 1
            elif action == "decrease":
                it["quantity"] = max(1, it.get("quantity", 1) - 1)
            elif action == "set":
                try:
                    it["quantity"] = max(1, int(new_qty))
                except Exception:
                    pass
            break

    if not item:
        return jsonify({"success": False, "error": "Item not found in cart"}), 404

    subtotal = item["price"] * item["quantity"]
    total = sum(i["price"] * i["quantity"] for i in cart)
    session["cart"] = cart
    session.modified = True

    return jsonify({"success": True, "quantity": item["quantity"], "subtotal": subtotal, "total": total})

# -------------------------
# Non-AJAX (fallback) update quantity (form submit)
# -------------------------
@app.route("/update_quantity/<product_id>", methods=["POST"])
def update_quantity(product_id):
    packet = request.form.get("packet")
    action = request.form.get("action")
    new_qty = request.form.get("quantity") or request.form.get("new_qty")
    cart = session.get("cart", [])
    item = None

    for it in cart:
        if str(it.get("id")) == product_id and (packet is None or it.get("packet") == packet):
            item = it
            if action == "increase":
                it["quantity"] = it.get("quantity", 0) + 1
            elif action == "decrease":
                it["quantity"] = max(1, it.get("quantity", 1) - 1)
            elif action == "set":
                try:
                    it["quantity"] = max(1, int(new_qty))
                except Exception:
                    pass
            break

    if item:
        session["cart"] = cart
        session.modified = True
        flash("Cart updated!", "success")
    else:
        flash("Item not found in cart.", "warning")

    return redirect(url_for("view_cart"))

# -------------------------
# Checkout & Orders
# -------------------------
@app.route("/checkout")
def checkout():
    cart = session.get("cart", [])
    if not cart:
        flash("Cart is empty!", "danger")
        return redirect(url_for("home"))
    total = sum(item["price"] * item["quantity"] for item in cart)
    return render_template("checkout.html", cart_items=cart, total_price=total, cart_count=get_cart_count())

@app.route("/place_order", methods=["POST"])
def place_order():
    name = request.form.get("name")
    phone = request.form.get("phone")
    email = request.form.get("email")
    address_text = request.form.get("address")
    payment_method = request.form.get("payment")
    cart = session.get("cart", [])

    if not cart:
        flash("Cart is empty!", "danger")
        return redirect(url_for("home"))

    items = []
    for item in cart:
        subtotal = item["price"] * item["quantity"]
        items.append({
            "name": item.get("name"),
            "packet": item.get("packet"),
            "qty": item.get("quantity"),
            "price": item.get("price"),
            "subtotal": subtotal
        })

    total_amount = sum(i["subtotal"] for i in items)

    payment_method = (payment_method or "").upper()

    if payment_method == "COD":
        order_status = "PLACED"
        payment_status = "COD"
    else:
        order_status = "PAYMENT_PENDING"
        payment_status = "PENDING"

    order = {
        "order_id": str(uuid.uuid4())[:8].upper(),
        "name": name,
        "phone": phone,
        "email": email,
        "address": address_text,
        "items": items,
        "total_amount": total_amount,
        "payment": {
            "method": payment_method,
            "status": payment_status,
            "transaction_id": None
        },
        "status": order_status,
        "created_at": datetime.now(),
        "updated_at": datetime.now(),
        "user_id": session.get("user_id"),
        "status_history": [{
            "status": order_status,
            "timestamp": datetime.now()
        }]
    }

    orders_col.insert_one(order)
    session["cart"] = []
    flash("Order placed!", "success")
    return redirect(url_for("thank_you", order_id=order["order_id"]))


@app.route("/thank_you/<order_id>")
def thank_you(order_id):
    return render_template("thank_you.html", order_id=order_id, cart_count=0)

# -------------------------
# Customer Authentication (signup/login/logout)
# -------------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")

        # 1️⃣ Empty field validation
        if not all([name, email, phone, password]):
            flash("All fields are required.", "danger")
            return redirect(url_for("signup"))

        # 2️⃣ Name validation
        if len(name) < 3:
            flash("Name must be at least 3 characters long.", "warning")
            return redirect(url_for("signup"))

        # 3️⃣ Email validation
        email_regex = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
        if not re.match(email_regex, email):
            flash("Please enter a valid email address.", "danger")
            return redirect(url_for("signup"))

        # 4️⃣ Phone validation (10 digits)
        if not phone.isdigit() or len(phone) != 10:
            flash("Phone number must be exactly 10 digits.", "danger")
            return redirect(url_for("signup"))

        # 5️⃣ Password validation
        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return redirect(url_for("signup"))

        # 6️⃣ Check existing user
        if users_col.find_one({"$or": [{"email": email}, {"phone": phone}]}):
            flash("Email or phone already registered.", "danger")
            return redirect(url_for("signup"))

        # 7️⃣ Hash password
        hashed_password = generate_password_hash(password)

        # 8️⃣ Insert user
        result = users_col.insert_one({
            "name": name,
            "email": email,
            "phone": phone,
            "password": hashed_password,
            "role": "customer",
            "created_at": datetime.now()
        })

        # 9️⃣ Auto-login
        session["user_id"] = str(result.inserted_id)
        session["name"] = name
        session["email"] = email
        session["mobile"] = phone

        flash("Account created successfully!", "success")
        return redirect(url_for("home"))

    return render_template("signup.html", cart_count=get_cart_count())

# -------------------------
# Shared Login for customers + admins
# -------------------------
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        email_or_phone = request.form.get("email_or_phone")
        password = request.form.get("password")

        # Find by email or phone
        user = users_col.find_one({
            "$or": [
                {"email": email_or_phone},
                {"phone": email_or_phone}
            ]
        })

        if user and check_password_hash(user.get("password", ""), password):
            session.permanent = True
            # Save full details in session
            session["user_id"] = str(user.get("_id"))
            session["name"] = user.get("name", "")
            session["email"] = user.get("email", "")     # ✔ FIXED
            session["mobile"] = user.get("phone", "")    # ✔ FIXED
            session["role"] = user.get("role", "customer")

            flash("Logged in!", "success")

            # admins go to admin dashboard
            if session.get("role") == "admin":
                return redirect(url_for("admin_dashboard"))

            return redirect(url_for("home"))

        flash("Invalid credentials.", "danger")
        return redirect(url_for("login"))

    return render_template("login.html", cart_count=get_cart_count())
    
# -------------------------
# Admin Dashboard
# -------------------------
@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    total_orders = orders_col.count_documents({"status": {"$ne": "SHIPPED"}})
    unread_messages = get_admin_unread_count()
    return render_template(
        "admin_dashboard.html",
        total_orders=total_orders,
        total_messages=unread_messages
    )


# -------------------------
# Admin Orders list + alias endpoint (so templates using either name work)
# -------------------------
@app.route("/admin/orders", endpoint="admin_view_orders")
@app.route("/admin/orders", endpoint="admin_orders")
def admin_view_orders():
    if not session.get("role") == "admin":
        flash("Please login as admin to access this page.", "danger")
        return redirect(url_for("login"))

    search = request.args.get("search", "").strip()
    sort = request.args.get("sort", "desc")
    query = {}
    if search:
        query["$or"] = [
            {"phone": {"$regex": search, "$options": "i"}},
            {"order_id": {"$regex": search, "$options": "i"}},
            {"name": {"$regex": search, "$options": "i"}}
        ]

    cursor = orders_col.find(query)
    if sort in ("asc", "date_asc", "date_ascending"):
        cursor = cursor.sort("created_at", 1)
    else:
        cursor = cursor.sort("created_at", -1)

    orders = list(cursor)
    for o in orders:
        o["_id"] = str(o.get("_id"))
        o.setdefault("items", [])
        o.setdefault("status", "Pending")
        o["total"] = o.get("total_amount", 0)
        ca = o.get("created_at")
        o["created_at"] = ca.strftime("%Y-%m-%d %H:%M") if isinstance(ca, datetime) else str(ca)
    return render_template("admin_orders.html", orders=orders, search=search, sort=sort)

# Update order status (template may call this via order_id)
@app.route("/admin/orders/<order_id>/status", methods=["POST"])
def update_order_status(order_id):
    if session.get("role") != "admin":
        flash("Please login as admin to access this page.", "danger")
        return redirect(url_for("login"))

    new_status = request.form.get("status")
    query = {"order_id": order_id}
    if orders_col.count_documents(query) == 0:
        if ObjectId.is_valid(order_id):
            query = {"_id": ObjectId(order_id)}
    orders_col.update_one(query, {"$set": {"status": new_status, "updated_at": datetime.now()}})
    flash("Order updated.", "success")
    return redirect(url_for("admin_view_orders"))

# View single order
@app.route("/admin/orders/<order_id>")
def admin_view_order(order_id):
    if session.get("role") != "admin":
        flash("Please login as admin to access this page.", "danger")
        return redirect(url_for("login"))

    order = orders_col.find_one({"order_id": order_id})
    if not order and ObjectId.is_valid(order_id):
        order = orders_col.find_one({"_id": ObjectId(order_id)})
    if not order:
        flash("Order not found.", "warning")
        return redirect(url_for("admin_view_orders"))

    order.setdefault("items", [])
    for idx, it in enumerate(order["items"]):
        if isinstance(it, dict):
            it.setdefault("name", it.get("name", f"Item {idx+1}"))
            if "qty" not in it and "quantity" in it:
                it["qty"] = it.pop("quantity")
            it.setdefault("qty", it.get("qty", 1))
            it.setdefault("price", it.get("price", 0.0))
            it.setdefault("subtotal", it.get("subtotal", it["price"] * it["qty"]))
        else:
            order["items"][idx] = {"name": str(it), "qty": 1, "price": 0.0, "subtotal": 0.0}

    order["_id"] = str(order.get("_id"))
    order["total"] = order.get("total_amount", sum(i.get("subtotal", 0) for i in order["items"]))
    ca = order.get("created_at")
    order["created_at"] = ca.strftime("%Y-%m-%d %H:%M") if isinstance(ca, datetime) else str(ca)
    order.setdefault("status", order.get("status", "Pending"))

    return render_template("admin_view_order.html", order=order)

# -------------------------
# Admin Inquiries
# -------------------------
@app.route("/admin/inquiries")
def admin_inquiries():
    if session.get("role") != "admin":
        flash("Please login as admin.", "danger")
        return redirect(url_for("login"))

    all_inquiries = list(messages_col.find().sort("created_at", -1))
    read, unread = [], []

    for inquiry in all_inquiries:
        inquiry["_id"] = str(inquiry["_id"])
        ca = inquiry.get("created_at")
        inquiry["created_at"] = ca.strftime("%Y-%m-%d %H:%M") if isinstance(ca, datetime) else str(ca)
        inquiry.setdefault("replies", [])
        inquiry.setdefault("read", bool(inquiry.get("read", False)))
        inquiry.setdefault("status", inquiry.get("status", "New"))
        if inquiry.get("read", False):
            read.append(inquiry)
        else:
            unread.append(inquiry)

    return render_template("admin_inquiries.html", read=read, unread=unread)

@app.route("/admin/inquiries/<inquiry_id>", methods=["GET", "POST"])
def admin_view_inquiry(inquiry_id):
    if session.get("role") != "admin":
        flash("Please login as admin to access this page.", "danger")
        return redirect(url_for("login"))

    try:
        obj_id = ObjectId(inquiry_id)
    except Exception:
        flash("Invalid inquiry id.", "danger")
        return redirect(url_for("admin_inquiries"))

    inquiry = messages_col.find_one({"_id": obj_id})
    if not inquiry:
        flash("Not found.", "warning")
        return redirect(url_for("admin_inquiries"))

    # Mark as read
    try:
        messages_col.update_one(
            {"_id": obj_id},
            {"$set": {"read": True, "updated_at": datetime.now()}}
        )
    except Exception:
        pass

    # POST = Admin Reply
    if request.method == "POST":
        reply_message = request.form.get("reply_message") or request.form.get("reply") or ""
        reply_message = reply_message.strip()

        if not reply_message:
            flash("Reply cannot be empty.", "warning")
            return redirect(url_for("admin_view_inquiry", inquiry_id=inquiry_id))

        admin_name = session.get("name", "Admin")

        # Email content
        subject = "Reply from BERG SPICES"
        body = f"Hello {inquiry.get('name')},\n\n{reply_message}\n\nRegards,\n{admin_name}"
        html = f"<p>Hello {inquiry.get('name')},</p><p>{reply_message.replace(chr(10), '<br/>')}</p><p>Regards,<br>{admin_name}</p>"

        sent = send_email(subject, body, inquiry.get("email"), html_body=html)

        if not sent:
            flash("Failed to send reply email.", "warning")
        else:
            flash("Reply sent successfully.", "success")

        reply_doc = {
            "admin_name": admin_name,
            "message": reply_message,
            "timestamp": datetime.now(),
            "from": "admin",
            "read_by_user": False
        }



        messages_col.update_one(
            {"_id": obj_id},
            {
                "$push": {"replies": reply_doc},
                "$set": {"status": "Replied", "updated_at": datetime.now()}
            }
        )

        return redirect(url_for("admin_view_inquiry", inquiry_id=inquiry_id))

    # GET → render inquiry page
    # GET → normalize inquiry for template
    inquiry["_id"] = str(inquiry["_id"])
    inquiry["created_at_fmt"] = format_dt(inquiry.get("created_at"))
    inquiry.setdefault("replies", [])
    inquiry.setdefault("status", "New")

    for reply in inquiry["replies"]:
        reply["timestamp_fmt"] = format_dt(reply.get("timestamp"))
    inquiry["_id"] = str(inquiry["_id"])
    inquiry.setdefault("replies", [])
    inquiry.setdefault("status", "New")

    return render_template("admin_view_inquiry.html", inquiry=inquiry)
    
# Provide an explicit reply endpoint for templates that reference admin_reply_inquiry
@app.route("/admin/inquiries/<inquiry_id>/reply", methods=["POST"], endpoint="admin_reply_inquiry")
def admin_reply_inquiry(inquiry_id):
    if session.get("role") != "admin":
        flash("Please login as admin.", "danger")
        return redirect(url_for("login"))

    try:
        obj_id = ObjectId(inquiry_id)
    except Exception:
        flash("Invalid inquiry id.", "danger")
        return redirect(url_for("admin_inquiries"))

    inquiry = messages_col.find_one({"_id": obj_id})
    if not inquiry:
        flash("Inquiry not found.", "warning")
        return redirect(url_for("admin_inquiries"))

    reply_message = request.form.get("reply") or request.form.get("reply_message") or ""
    reply_message = reply_message.strip()
    if not reply_message:
        flash("Reply cannot be empty.", "warning")
        return redirect(url_for("admin_view_inquiry", inquiry_id=inquiry_id))

    admin_name = session.get("name", "Admin")

    # FIXED reply structure
    reply_doc = {
        "from": "admin",
        "message": reply_message,
        "timestamp": datetime.now(),
        "read_by_user": False,
        "read_by_admin": True
    }

    messages_col.update_one(
        {"_id": obj_id},
        {
            "$push": {"replies": reply_doc},
            "$set": {"status": "Replied", "updated_at": datetime.now()}
        }
    )

    flash("Reply sent successfully.", "success")
    return redirect(url_for("admin_view_inquiry", inquiry_id=inquiry_id))

# Admin: delete an inquiry
@app.route("/admin/inquiries/delete/<inquiry_id>", methods=["POST"])
@admin_required
def admin_delete_inquiry(inquiry_id):
    try:
        messages_col.delete_one({"_id": ObjectId(inquiry_id)})
        flash("Inquiry deleted successfully!", "success")
    except Exception as e:
        print("Delete inquiry error:", e)
        flash("Failed to delete inquiry.", "danger")
    return redirect(url_for("admin_inquiries"))

# Admin: toggle read/unread
@app.route("/admin/inquiries/<inquiry_id>/toggle_read", methods=["POST"])
def admin_toggle_read(inquiry_id):
    if session.get("role") != "admin":
        return jsonify({"success": False, "error": "unauthorized"}), 403
    try:
        if not ObjectId.is_valid(inquiry_id):
            return jsonify({"success": False, "error": "invalid id"}), 400
        obj_id = ObjectId(inquiry_id)
        current = messages_col.find_one({"_id": obj_id}, {"read": 1})
        new_val = not bool(current.get("read", False))
        messages_col.update_one({"_id": obj_id}, {"$set": {"read": new_val, "updated_at": datetime.now()}})
        return jsonify({"success": True, "read": new_val})
    except Exception as e:
        print("toggle_read error:", e)
        return jsonify({"success": False, "error": "server error"}), 500

# -------------------------
# Live search (used by index)
# -------------------------
@app.route("/live_search")
def live_search():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify([])
    results = list(products_col.find({"name": {"$regex": q, "$options": "i"}}, {"_id": 1, "name": 1, "image": 1}).limit(10))
    for r in results:
        r["_id"] = str(r.get("_id"))
    return jsonify(results)

# -------------------------
# Admin order update with logs + notifications (FIXED)
# -------------------------
@app.route("/admin/orders/<order_id>/update_status", methods=["POST"], endpoint="admin_update_order_status")
def admin_update_order_status(order_id):

    if session.get("role") != "admin":
        flash("Please login as admin.", "danger")
        return redirect(url_for("login"))

    new_status = request.form.get("status")
    comment = request.form.get("comment", "").strip()

    # Valid statuses that REQUIRE comment
    COMMENT_REQUIRED = ["DELAYED", "REFUND_INITIATED", "REFUNDED"]

    if new_status not in ORDER_STATUSES:
        flash("Invalid order status.", "danger")
        return redirect(url_for("admin_view_orders"))

    if new_status in COMMENT_REQUIRED and not comment:
        flash("Comment is required for this status.", "warning")
        return redirect(url_for("admin_view_order", order_id=order_id))

    try:
        order = orders_col.find_one({"_id": ObjectId(order_id)})
        if not order:
            flash("Order not found.", "warning")
            return redirect(url_for("admin_view_orders"))
    except Exception:
        flash("Invalid order ID.", "danger")
        return redirect(url_for("admin_view_orders"))

    # -------------------------
    # Create log entry (IMPORTANT FIX)
    # -------------------------
    log_entry = {
        "timestamp": datetime.now().strftime("%d %b %Y, %I:%M %p"),
        "action": f"Status changed to {new_status}",
        "comment": comment if comment else None
    }

    # -------------------------
    # Update DB
    # -------------------------
    orders_col.update_one(
        {"_id": order["_id"]},
        {
            "$set": {
                "status": new_status,
                "updated_at": datetime.now()
            },
            "$push": {
                "logs": log_entry
            }
        }
    )

    # -------------------------
    # Notifications
    # -------------------------
    subject = f"Update on your Order {order['order_id']}"
    body = f"Dear {order['name']},\n\nYour order status is now: {new_status}."

    if comment:
        body += f"\n\nAdmin Comment:\n{comment}"

    body += "\n\nThank you for shopping with BERG SPICES!"

    send_email(subject, body, order["email"])
    send_sms(
        order["phone"],
        f"BERG SPICES: Order {order['order_id']} status updated to {new_status}."
    )

    flash("Order updated successfully!", "success")
    return redirect(url_for("admin_view_order", order_id=order_id))


# -- admin NEW reply notification (customer -> admin)
#--reply_to_admin(inquiry_id)

@app.route("/customer/inquiries/<inquiry_id>/reply", methods=["POST"])
@login_required
def reply_to_admin(inquiry_id):
    reply_message = request.form.get("reply_message")

    if not reply_message:
        return redirect(url_for("my_messages"))

    inquiries = messages_col
    reply_doc = {
        "message": reply_message,
        "timestamp": datetime.now(),
        "from": "customer",
        "read_by_user": True,  # customer already read it
        "read_by_admin": False  # admin has not read it yet
    }

    inquiries.update_one(
        {"_id": ObjectId(inquiry_id)},
        {
            "$push": {"replies": reply_doc},
            "$set": {"updated_at": datetime.now(), "status": "Replied"}
        }
    )

    flash("Reply sent to admin.", "success")
    return redirect(url_for("my_messages"))

# -------------------------
# Customer Dashboard (Orders + Profile + Cart)
# -------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session.get("user_id")

    # Fetch logged-in user profile
    try:
        user = users_col.find_one({"_id": ObjectId(user_id)})
    except Exception:
        user = None

    # Fetch orders placed by this user
    orders = list(
        orders_col.find({"user_id": user_id}).sort("created_at", -1)
    )

    # Normalize order fields for template safety
    for order in orders:
        order["_id"] = str(order.get("_id"))
        order.setdefault("order_id", "N/A")
        order.setdefault("status", "Pending")
        order.setdefault("total_amount", 0)
        order.setdefault("phone", "-")
        order.setdefault("payment", {})
        order.setdefault("items", [])

        ca = order.get("created_at")
        order["created_at_str"] = (
            ca.strftime("%d %b %Y") if isinstance(ca, datetime) else "-"
        )

    # Cart is session-based in your app
    cart_items = session.get("cart", [])

    return render_template(
        "dashboard.html",
        user=user,
        orders=orders,
        cart_items=cart_items,
        cart_count=get_cart_count()
    )

# -------------------------
# Customer: View single order
# -------------------------
@app.route("/my/orders/<order_id>")
@login_required
def customer_order_detail(order_id):

    order = orders_col.find_one({
        "order_id": order_id,
        "user_id": session.get("user_id")
    })

    if not order:
        flash("Order not found.", "warning")
        return redirect(url_for("dashboard"))

    # -----------------------------
    # Normalize / default fields
    # -----------------------------
    order["_id"] = str(order["_id"])
    order.setdefault("items", [])
    order.setdefault("payment", None)
    order.setdefault("logs", [])
    order.setdefault("status", "PLACED")

    # -----------------------------
    # Created date formatting
    # -----------------------------
    created_at = order.get("created_at")
    order["created_at_str"] = (
        created_at.strftime("%d %b %Y, %I:%M %p")
        if isinstance(created_at, datetime)
        else "-"
    )

    # -----------------------------
    # STATUS → DISPLAY STATUS MAPPING (CRITICAL FIX)
    # -----------------------------
    STATUS_DISPLAY_MAP = {
        "PLACED": "Pending",
        "PAYMENT_PENDING": "Pending",
        "PREPARING": "Packed",
        "SHIPPED": "Shipped",
        "DELIVERED": "Delivered",

        # Important edge cases
        "DELAYED": "Packed",
        "CANCELLED": "Cancelled",
        "REFUND_INITIATED": "Cancelled",
        "REFUNDED": "Cancelled",
    }

    order["display_status"] = STATUS_DISPLAY_MAP.get(
        order["status"],
        "Pending"
    )

    # -----------------------------
    # Render page
    # -----------------------------
    return render_template(
        "customer_order_detail.html",
        order=order,
        cart_count=get_cart_count()
    )


# -------------------------
# Customer: view their own inquiries & replies (must be logged in)
# -------------------------
@app.route("/my/messages")
@login_required
def my_messages():
    user_id = session.get("user_id")
    try:
        inquiries = list(messages_col.find({"user_id": ObjectId(user_id)}))
    except Exception:
        inquiries = []

    for inquiry in inquiries:
        unread_count = 0
        for reply in inquiry.get("replies", []):
            # Convert timestamp to string if datetime
            ts = reply.get("timestamp")
            if isinstance(ts, datetime):
                reply["timestamp_str"] = ts.strftime("%Y-%m-%d %H:%M")
            else:
                reply["timestamp_str"] = str(ts)

            # Count unread replies from admin
            if reply.get("from") == "admin" and not reply.get("read_by_user", False):
                unread_count += 1
                reply["read_by_user"] = True  # mark as read

        # Save updated replies back to DB
        messages_col.update_one(
            {"_id": inquiry["_id"]},
            {"$set": {"replies": inquiry.get("replies", [])}}
        )
        inquiry["unread_replies_count"] = unread_count

    return render_template(
        "customer_messages.html",
        inquiries=inquiries,
        cart_count=get_cart_count()
    )
# Admin unread messages count for dashboard
def get_admin_unread_count():
    inquiries = list(messages_col.find({}))
    unread_total = 0
    for inquiry in inquiries:
        # First-time inquiries with no replies are unread
        if not inquiry.get("read", False) and not inquiry.get("replies"):
            unread_total += 1
        else:
            # Any customer reply not read by admin
            for reply in inquiry.get("replies", []):
                if reply.get("from") == "customer" and not reply.get("read_by_admin", False):
                    unread_total += 1
                    break
    return unread_total

# User unread messages count
def get_unread_messages_count(user_id):
    try:
        user_id = ObjectId(user_id)
    except:
        return 0

    unread_total = 0
    inquiries = list(messages_col.find({"user_id": user_id}))

    for inquiry in inquiries:
        for reply in inquiry.get("replies", []):
            # Count only admin replies unread by user
            if reply.get("from") == "admin" and not reply.get("read_by_user", False):
                unread_total += 1
                break

    return unread_total

# --------------------
# Edit Profile - Works for Admin + Customer
# --------------------
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user_id = session.get("user_id")

    # Always fetch fresh user from DB
    try:
        user = users_col.find_one({"_id": ObjectId(user_id)})
    except Exception:
        user = None

    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("logout"))

    if request.method == "POST":

        # ---------- UPDATE PROFILE ----------
        if "update_profile" in request.form:
            users_col.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": {
                    "name": request.form.get("name"),
                    "phone": request.form.get("phone"),
                    "address": request.form.get("address")
                }}
            )
            flash("Profile updated successfully", "success")
            return redirect(url_for("profile"))

        # ---------- CHANGE PASSWORD ----------
        if "change_password" in request.form:
            current_password = request.form.get("current_password")
            new_password = request.form.get("new_password")
            confirm_password = request.form.get("confirm_password")

            # ✅ Correct password check
            if not check_password_hash(user["password"], current_password):
                flash("Current password is incorrect", "danger")
                return redirect(url_for("profile"))

            if new_password != confirm_password:
                flash("New passwords do not match", "warning")
                return redirect(url_for("profile"))

            users_col.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": {"password": generate_password_hash(new_password)}}
            )

            flash("Password changed successfully", "success")
            return redirect(url_for("profile"))

    return render_template(
        "profile.html",
        user=user,
        cart_count=get_cart_count()
    )

#-------------------
#Invoice pdf
#-------------------
@app.route("/invoice/pdf/<order_id>")
@login_required
def download_invoice_pdf(order_id):

    order = orders_col.find_one({
        "order_id": order_id,
        "user_id": session["user_id"]
    })

    if not order:
        flash("Order not found", "danger")
        return redirect(url_for("dashboard"))

    os.makedirs("invoices", exist_ok=True)
    file_path = f"invoices/Invoice_{order_id}.pdf"

    doc = SimpleDocTemplate(
        file_path,
        pagesize=A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=50
    )

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="CompanyName",
        fontSize=14,
        textColor=colors.white,
        leading=16,
        spaceAfter=2
    ))

    styles.add(ParagraphStyle(
        name="CompanyTagline",
        fontSize=9,
        textColor=colors.white
    ))

    styles.add(ParagraphStyle(
        name="FooterText",
        fontSize=8,
        textColor=colors.grey,
        alignment=1
    ))

    elements = []

    # ───────────────── HEADER ─────────────────
    logo = Image("static/logo.jpg", width=3.5*cm, height=3*cm)

    header_table = Table([
        [
            logo,
            Paragraph(
                "<b>BERG SPICES</b><br/>Pure Aroma. Pure Taste",
                styles["CompanyName"]
            )
        ]
    ], colWidths=[4.5*cm, 11.5*cm])

    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#198754")),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING", (0,0), (-1,-1), 14),
        ("RIGHTPADDING", (0,0), (-1,-1), 14),
        ("TOPPADDING", (0,0), (-1,-1), 12),
        ("BOTTOMPADDING", (0,0), (-1,-1), 12),
    ]))

    elements.append(header_table)
    elements.append(Spacer(1, 18))

    # ───────────────── INVOICE META ─────────────────
    meta_table = Table([
        ["Invoice No:", order["order_id"], "Date:", order["created_at"].strftime("%d %b %Y")]
    ], colWidths=[3*cm, 5*cm, 2.5*cm, 4.5*cm])

    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0,0), (-1,-1), "Helvetica"),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))

    elements.append(meta_table)
    elements.append(Spacer(1, 14))

    # ───────────────── BILL TO ─────────────────
    elements.append(Paragraph("<b>Billed To</b>", styles["Normal"]))
    elements.append(Spacer(1, 4))
    elements.append(Paragraph(order.get("name", ""), styles["Normal"]))
    elements.append(Paragraph(order.get("phone", ""), styles["Normal"]))
    elements.append(
        Paragraph(order.get("address", "").replace("\n", "<br/>"), styles["Normal"])
    )

    elements.append(Spacer(1, 16))

    # ───────────────── ITEMS TABLE ─────────────────
    table_data = [["Item", "Packet", "Qty", "Price", "Total"]]

    for item in order.get("items", []):
        table_data.append([
            item.get("name", ""),
            item.get("packet", "-"),
            str(item.get("qty", 0)),
            f"₹{item.get('price', 0)}",
            f"₹{item.get('subtotal', 0)}"
        ])

    items_table = Table(
        table_data,
        colWidths=[6*cm, 3*cm, 2*cm, 2.5*cm, 2.5*cm]
    )

    items_table.setStyle(TableStyle([
        ("GRID", (0,0), (-1,-1), 0.75, colors.grey),
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#e6f4ea")),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("ALIGN", (2,1), (-1,-1), "RIGHT"),
        ("TOPPADDING", (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
    ]))

    elements.append(items_table)
    elements.append(Spacer(1, 14))

    # ───────────────── TOTAL ─────────────────
    total_table = Table([
        ["", "Grand Total:", f"₹{order.get('total_amount', 0)}"]
    ], colWidths=[10.5*cm, 3*cm, 3.5*cm])

    total_table.setStyle(TableStyle([
        ("FONTNAME", (1,0), (-1,0), "Helvetica-Bold"),
        ("ALIGN", (2,0), (2,0), "RIGHT"),
        ("TOPPADDING", (0,0), (-1,-1), 10),
    ]))

    elements.append(total_table)

    elements.append(Spacer(1, 30))

    # ───────────────── FOOTER ─────────────────
    elements.append(Paragraph(
        "This is a computer-generated invoice and does not require a signature.",
        styles["FooterText"]
    ))
    elements.append(Spacer(1, 4))
    elements.append(Paragraph(
        "Thank you for shopping with BERG SPICES.",
        styles["FooterText"]
    ))

    doc.build(elements)

    return send_file(file_path, as_attachment=True)

#-------------------
# Cancel Order
#-------------------
@app.route("/cancel-order/<order_id>", methods=["POST"])
@login_required
def cancel_order(order_id):

    order = orders_col.find_one({
        "order_id": order_id,
        "user_id": session["user_id"]
    })

    if not order:
        flash("Order not found", "danger")
        return redirect(url_for("dashboard"))

    if normalize_order_status(order.get("status")) in ["SHIPPED", "DELIVERED"]:
        flash("Order cannot be cancelled after shipping", "warning")
        return redirect(url_for("customer_order_detail", order_id=order_id))

    orders_col.update_one(
        {"order_id": order_id},
        {
            "$set": {
                "status": "CANCELLED",
                "updated_at": datetime.now()
            }
        }
    )

    flash("Order cancelled successfully", "success")
    return redirect(url_for("dashboard"))  # ✅ FIXED

#-----------------------
# privacy-policy
#-----------------------
@app.route("/privacy-policy")
def privacy_policy():
    return render_template("privacy_policy.html", cart_count=get_cart_count())


@app.route("/terms-and-conditions")
def terms_conditions():
    return render_template("terms_conditions.html", cart_count=get_cart_count())

#-------------------
def generate_reset_token(email):
    s = URLSafeTimedSerializer(current_app.secret_key)
    return s.dumps(email, salt='password-reset')

def verify_reset_token(token, expiration=3600):
    s = URLSafeTimedSerializer(current_app.secret_key)
    try:
        return s.loads(token, salt='password-reset', max_age=expiration)
    except:
        return None

@app.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def forgot_password():
    if request.method == 'POST':
        identifier = request.form.get('email_or_phone')

        user = users_col.find_one({
            "$or": [
                {"email": identifier},
                {"phone": identifier}
            ]
        })

        if user:
            otp = generate_otp()

            users_col.update_one(
                {"_id": user["_id"]},
                {"$set": {
                    "reset_otp": generate_password_hash(otp),
                    "otp_expires_at": otp_expiry(5)
                }}
            )

            # 🔔 SEND OTP (email / sms)
            print("PASSWORD RESET OTP:", otp)

            # Example email
            send_email(
                "BERG SPICES Password Reset OTP",
                f"Your OTP is {otp}. It is valid for 5 minutes.",
                user["email"]
            )

        flash("If the account exists, an OTP has been sent.", "success")
        return redirect(url_for('verify_otp'))

    return render_template('forgot_password.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def verify_otp():
    if request.method == 'POST':
        identifier = request.form.get('email_or_phone')
        otp = request.form.get('otp')

        user = users_col.find_one({
            "$or": [
                {"email": identifier},
                {"phone": identifier}
            ]
        })

        if not user or not user.get("reset_otp"):
            flash("Invalid OTP", "danger")
            return redirect(url_for('verify_otp'))

        # ⏱️ Check expiry
        if datetime.now() > user.get("otp_expires_at", datetime.min):
            flash("OTP expired", "danger")
            return redirect(url_for('forgot_password'))

        if not check_password_hash(user["reset_otp"], otp):
            flash("Invalid OTP", "danger")
            return redirect(url_for('verify_otp'))

        # ✅ OTP OK → allow password reset
        session["reset_user_id"] = str(user["_id"])
        return redirect(url_for('reset_password'))

    return render_template('verify_otp.html')



@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    user_id = session.get("reset_user_id")
    if not user_id:
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')

        if password != confirm:
            flash("Passwords do not match", "warning")
            return redirect(url_for('reset_password'))

        users_col.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {
                "password": generate_password_hash(password)
            },
            "$unset": {
                "reset_otp": "",
                "otp_expires_at": ""
            }}
        )

        session.pop("reset_user_id", None)
        flash("Password reset successful. Please login.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')


#-------------------------
def generate_otp():
    return str(random.randint(100000, 999999))

def otp_expiry(minutes=5):
    return datetime.now() + timedelta(minutes=minutes)

#--------------
#Logout
#--------------
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("home"))


# -------------------------
# Run app
# -------------------------
if __name__ == "__main__":
    app.run()
