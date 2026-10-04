from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import requests
import sqlite3
import os
import random
from datetime import datetime, timedelta

from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash


# =========================================================
# SQLite Database - No XAMPP / MySQL Required
# =========================================================

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_DIR = os.path.join(BASE_DIR, "database")
DATABASE_PATH = os.path.join(DATABASE_DIR, "app.db")

os.makedirs(DATABASE_DIR, exist_ok=True)

connection = sqlite3.connect(
    DATABASE_PATH,
    check_same_thread=False
)

connection.row_factory = sqlite3.Row


# =========================================================
# Database Initialization
# =========================================================

def init_db():

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullname TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            is_verified INTEGER NOT NULL DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS otp_verification (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            otp_code TEXT NOT NULL,
            purpose TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            verified INTEGER NOT NULL DEFAULT 0,
            attempts INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # =====================================================
    # Search History
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS search_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            service TEXT NOT NULL,
            location TEXT,
            radius INTEGER,
            searched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    connection.commit()
    cursor.close()


# =========================================================
# Flask App
# =========================================================

app = Flask(__name__)

app.secret_key = "sevasetu_secret"


# =========================================================
# Brevo SMTP Configuration
# =========================================================

app.config["MAIL_SERVER"] = "smtp-relay.brevo.com"
app.config["MAIL_PORT"] = 2525
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.environ.get("BREVO_SMTP_LOGIN")
app.config["MAIL_PASSWORD"] = os.environ.get("BREVO_SMTP_KEY")

mail = Mail(app)


# Create database tables
init_db()


# =========================================================
# Gujarat District Coordinates
# =========================================================

districts = {

    "Ahmedabad": (23.0225, 72.5714),

    "Surat": (21.1702, 72.8311),

    "Rajkot": (22.3039, 70.8022),

    "Vadodara": (22.3072, 73.1812),

    "Bhavnagar": (21.7645, 72.1519),

    "Jamnagar": (22.4707, 70.0577),

    "Junagadh": (21.5222, 70.4579),

    "Anand": (22.5645, 72.9289),

    "Bharuch": (21.7051, 72.9959),

    "Gandhinagar": (23.2156, 72.6369)

}


# =========================================================
# Welcome Page
# =========================================================

@app.route("/")
def index():

    return render_template("welcome.html")


# =========================================================
# Home Page
# =========================================================

@app.route("/home")
def home():

    if not session.get("user_id"):

        return redirect("/login")

    return render_template("home.html")


# =========================================================
# Login
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        if not email or not password:

            return "Email and password are required."

        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT id, fullname, email, password, is_verified
            FROM users
            WHERE email=?
            """,
            (email,)
        )

        user = cursor.fetchone()

        cursor.close()

        if not user:

            return render_template(
                "login.html",
                error="Invalid Email or Password."
            )

        if user["is_verified"] != 1:

            return "Please verify your email with OTP before login."

        if not check_password_hash(
            user["password"],
            password
        ):

            return render_template(
                "login.html",
                error="Invalid Email or Password."
            )

        session["user_id"] = user["id"]

        session["user_name"] = user["fullname"]

        session["user_email"] = user["email"]

        return redirect("/home")

    return render_template("login.html")


# =========================================================
# Forgot Password
# =========================================================

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        if not email:

            return "Email is required."

        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT id, fullname, email, is_verified
            FROM users
            WHERE email=?
            """,
            (email,)
        )

        user = cursor.fetchone()

        if not user:

            cursor.close()

            return "Email not registered."

        if user["is_verified"] != 1:

            cursor.close()

            return "Please verify your email first."

        otp = str(
            random.randint(
                100000,
                999999
            )
        )

        expires_at = (
            datetime.now()
            + timedelta(minutes=5)
        )

        cursor.execute(
            """
            DELETE FROM otp_verification
            WHERE user_id=?
            AND purpose='forgot_password'
            """,
            (user["id"],)
        )

        cursor.execute(
            """
            INSERT INTO otp_verification
            (
                user_id,
                otp_code,
                purpose,
                expires_at
            )
            VALUES (?, ?, 'forgot_password', ?)
            """,
            (
                user["id"],
                otp,
                expires_at.isoformat(
                    sep=" "
                )
            )
        )

        connection.commit()

        try:

            msg = Message(
                subject="SevaSetu - Password Reset OTP",
                sender="smartnearby.app@gmail.com",
                recipients=[email]
            )

            msg.body = f"""
Hello {user["fullname"]},

Your password reset OTP for SevaSetu is:

{otp}

This OTP is valid for 5 minutes.

Please do not share this OTP with anyone.

Regards,
SevaSetu
"""

            mail.send(msg)

        except Exception as e:

            print(
                "EMAIL ERROR:",
                e
            )

            cursor.close()

            return (
                "Unable to send OTP email. "
                f"Error: {e}"
            )

        cursor.close()

        session["forgot_user_id"] = user["id"]

        session["forgot_email"] = email

        return redirect(
            "/verify-forgot-otp"
        )

    return render_template(
        "forgot-password.html"
    )


# =========================================================
# Verify Forgot Password OTP
# =========================================================

@app.route(
    "/verify-forgot-otp",
    methods=["GET", "POST"]
)
def verify_forgot_otp():

    user_id = session.get(
        "forgot_user_id"
    )

    if not user_id:

        return redirect(
            "/forgot-password"
        )

    if request.method == "POST":

        otp = request.form.get(
            "otp",
            ""
        ).strip()

        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM otp_verification
            WHERE user_id=?
            AND purpose='forgot_password'
            AND verified=0
            ORDER BY id DESC
            LIMIT 1
            """,
            (user_id,)
        )

        otp_record = cursor.fetchone()

        if not otp_record:

            cursor.close()

            return render_template(
                "verify-forgot-otp.html",
                email=session.get(
                    "forgot_email"
                ),
                error="OTP not found."
            )

        if datetime.now() > datetime.fromisoformat(
            otp_record["expires_at"]
        ):

            cursor.close()

            return render_template(
                "verify-forgot-otp.html",
                email=session.get(
                    "forgot_email"
                ),
                error=(
                    "OTP has expired. "
                    "Please try again."
                )
            )

        if otp != otp_record["otp_code"]:

            cursor.execute(
                """
                UPDATE otp_verification
                SET attempts = attempts + 1
                WHERE id=?
                """,
                (otp_record["id"],)
            )

            connection.commit()

            cursor.close()

            return render_template(
                "verify-forgot-otp.html",
                email=session.get(
                    "forgot_email"
                ),
                error=(
                    "Invalid OTP. "
                    "Please try again."
                )
            )

        cursor.execute(
            """
            UPDATE otp_verification
            SET verified=1
            WHERE id=?
            """,
            (otp_record["id"],)
        )

        connection.commit()

        cursor.close()

        session["reset_user_id"] = user_id

        return redirect(
            "/reset-password"
        )

    return render_template(
        "verify-forgot-otp.html",
        email=session.get(
            "forgot_email"
        )
    )


# =========================================================
# Reset Password
# =========================================================

@app.route(
    "/reset-password",
    methods=["GET", "POST"]
)
def reset_password():

    user_id = session.get(
        "reset_user_id"
    )

    if not user_id:

        return redirect(
            "/forgot-password"
        )

    if request.method == "POST":

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if not password or not confirm_password:

            return "All fields are required."

        if len(password) < 8:

            return render_template(
                "reset-password.html",
                error="🔐 Create a Strong Password",
                error_message=(
                    "Your password must contain at least "
                    "8 characters. Please choose a "
                    "stronger password."
                )
            )

        if password != confirm_password:

            return "Passwords do not match."

        hashed_password = generate_password_hash(
            password
        )

        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE users
            SET password=?
            WHERE id=?
            """,
            (
                hashed_password,
                user_id
            )
        )

        connection.commit()

        cursor.close()

        session.pop(
            "reset_user_id",
            None
        )

        session.pop(
            "forgot_user_id",
            None
        )

        session.pop(
            "forgot_email",
            None
        )

        return redirect("/login")

    return render_template(
        "reset-password.html"
    )


# =========================================================
# Signup
# =========================================================

@app.route(
    "/signup",
    methods=["GET", "POST"]
)
def signup():

    if request.method == "POST":

        fullname = request.form.get(
            "fullname",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        if not fullname or not email or not password:

            return "All fields are required."

        if len(password) < 8:

            return render_template(
                "signup.html",
                error="🔐 Create a Strong Password",
                error_message=(
                    "Your password must contain at least "
                    "8 characters. Please choose a "
                    "stronger password."
                )
            )

        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT id, is_verified
            FROM users
            WHERE email=?
            """,
            (email,)
        )

        existing_user = cursor.fetchone()

        if existing_user:

            if existing_user["is_verified"] == 1:

                cursor.close()

                return render_template(
                    "signup.html",
                    error="Email Already Registered",
                    error_message=(
                        "This email is already registered. "
                        "Please login or use another email."
                    )
                )

            user_id = existing_user["id"]

            hashed_password = generate_password_hash(
                password
            )

            cursor.execute(
                """
                UPDATE users
                SET fullname=?, password=?
                WHERE id=?
                """,
                (
                    fullname,
                    hashed_password,
                    user_id
                )
            )

        else:

            hashed_password = generate_password_hash(
                password
            )

            cursor.execute(
                """
                INSERT INTO users
                (
                    fullname,
                    email,
                    password,
                    is_verified
                )
                VALUES (?, ?, ?, 0)
                """,
                (
                    fullname,
                    email,
                    hashed_password
                )
            )

            connection.commit()

            user_id = cursor.lastrowid

        otp = str(
            random.randint(
                100000,
                999999
            )
        )

        expires_at = (
            datetime.now()
            + timedelta(minutes=5)
        )

        cursor.execute(
            """
            DELETE FROM otp_verification
            WHERE user_id=?
            AND purpose='signup'
            """,
            (user_id,)
        )

        cursor.execute(
            """
            INSERT INTO otp_verification
            (
                user_id,
                otp_code,
                purpose,
                expires_at
            )
            VALUES (?, ?, 'signup', ?)
            """,
            (
                user_id,
                otp,
                expires_at.isoformat(
                    sep=" "
                )
            )
        )

        connection.commit()

        try:

            msg = Message(
                subject="SevaSetu - Email Verification",
                sender="smartnearby.app@gmail.com",
                recipients=[email]
            )

            msg.body = f"""
Hello {fullname},

Thank you for registering with SevaSetu.

Your verification OTP is:

{otp}

This OTP is valid for 5 minutes.

Please do not share this OTP with anyone.

Regards,
SevaSetu
"""

            mail.send(msg)

        except Exception as e:

            print(
                "EMAIL ERROR:",
                e
            )

            cursor.close()

            return (
                "Unable to send OTP email. "
                f"Error: {e}"
            )

        cursor.close()

        session["otp_user_id"] = user_id

        session["otp_email"] = email

        return redirect(
            "/verify-otp"
        )

    return render_template(
        "signup.html"
    )


# =========================================================
# Verify Signup OTP
# =========================================================

@app.route(
    "/verify-otp",
    methods=["GET", "POST"]
)
def verify_otp():

    user_id = session.get(
        "otp_user_id"
    )

    if not user_id:

        return redirect("/signup")

    if request.method == "POST":

        otp = request.form.get(
            "otp",
            ""
        ).strip()

        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM otp_verification
            WHERE user_id=?
            AND purpose='signup'
            AND verified=0
            ORDER BY id DESC
            LIMIT 1
            """,
            (user_id,)
        )

        otp_record = cursor.fetchone()

        if not otp_record:

            cursor.close()

            return render_template(
                "verify-otp.html",
                email=session.get(
                    "otp_email"
                ),
                error="OTP not found."
            )

        if datetime.now() > datetime.fromisoformat(
            otp_record["expires_at"]
        ):

            cursor.close()

            return render_template(
                "verify-otp.html",
                email=session.get(
                    "otp_email"
                ),
                error=(
                    "OTP has expired. "
                    "Please signup again."
                )
            )

        if otp != otp_record["otp_code"]:

            cursor.execute(
                """
                UPDATE otp_verification
                SET attempts = attempts + 1
                WHERE id=?
                """,
                (otp_record["id"],)
            )

            connection.commit()

            cursor.close()

            return render_template(
                "verify-otp.html",
                email=session.get(
                    "otp_email"
                ),
                error=(
                    "Invalid OTP. "
                    "Please try again."
                )
            )

        cursor.execute(
            """
            UPDATE users
            SET is_verified=1
            WHERE id=?
            """,
            (user_id,)
        )

        cursor.execute(
            """
            UPDATE otp_verification
            SET verified=1
            WHERE id=?
            """,
            (otp_record["id"],)
        )

        connection.commit()

        cursor.execute(
            """
            SELECT id, fullname, email
            FROM users
            WHERE id=?
            """,
            (user_id,)
        )

        user = cursor.fetchone()

        cursor.close()

        session["user_id"] = user["id"]

        session["user_name"] = user["fullname"]

        session["user_email"] = user["email"]

        session.pop(
            "otp_user_id",
            None
        )

        session.pop(
            "otp_email",
            None
        )

        return redirect("/home")

    return render_template(
        "verify-otp.html",
        email=session.get(
            "otp_email"
        )
    )


# =========================================================
# Logout
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")


# =========================================================
# Search Page
# =========================================================

@app.route(
    "/search-page",
    methods=["POST"]
)
def search_page():

    # User must be logged in
    if not session.get("user_id"):

        return redirect("/login")

    search_type = request.form.get(
        "search_type"
    )

    service = request.form.get(
        "service",
        ""
    ).strip()

    try:

        radius = int(
            request.form.get(
                "radius",
                5000
            )
        )

    except (TypeError, ValueError):

        radius = 5000

    # -----------------------------------------------------
    # Address Search
    # -----------------------------------------------------

    if search_type == "address":

        address = request.form.get(
            "address",
            ""
        ).strip()

        if not address:

            return "Please enter an address."

        geo_url = (
            "https://nominatim.openstreetmap.org/search"
        )

        try:

            response = requests.get(
                geo_url,
                params={
                    "q": address,
                    "format": "json",
                    "limit": 1
                },
                headers={
                    "User-Agent": "SevaSetu/1.0"
                },
                timeout=30
            )

            print(
                "NOMINATIM STATUS:",
                response.status_code
            )

            print(
                "NOMINATIM RESPONSE:",
                response.text[:500]
            )

            response.raise_for_status()

            geo_data = response.json()

        except requests.exceptions.RequestException as e:

            print(
                "NOMINATIM ERROR:",
                e
            )

            return (
                "Unable to find the address right now. "
                "Please try again."
            )

        except ValueError:

            print(
                "NOMINATIM JSON ERROR"
            )

            return (
                "Invalid response received "
                "from location service."
            )

        if len(geo_data) == 0:

            return "Address not found."

        lat = float(
            geo_data[0]["lat"]
        )

        lon = float(
            geo_data[0]["lon"]
        )

        print(
            "Address:",
            address
        )

        print(
            "Latitude:",
            lat
        )

        print(
            "Longitude:",
            lon
        )

        district = address

    # -----------------------------------------------------
    # District Search
    # -----------------------------------------------------

    else:

        district = request.form.get(
            "district"
        )

        if district not in districts:

            return "Please select a valid district."

        lat, lon = districts[district]

    # =====================================================
    # SAVE SEARCH HISTORY
    # =====================================================

    try:

        user_id = session.get(
            "user_id"
        )

        if user_id:

            cursor = connection.cursor()

            cursor.execute(
                """
                INSERT INTO search_history
                (
                    user_id,
                    service,
                    location,
                    radius
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    user_id,
                    service if service else "Unknown",
                    district,
                    radius
                )
            )

            connection.commit()

            cursor.close()

            print(
                "SEARCH HISTORY SAVED:",
                user_id,
                service,
                district,
                radius
            )

    except Exception as e:

        print(
            "SEARCH HISTORY ERROR:",
            e
        )

    # =====================================================
    # Show Search Result Page
    # =====================================================

    return render_template(
        "result.html",
        district=district,
        lat=lat,
        lon=lon,
        service=service,
        radius=radius
    )


# =========================================================
# Search History
# =========================================================

@app.route("/history")
def history():

    user_id = session.get("user_id")

    if not user_id:

        return redirect("/login")

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id, service, location, radius, searched_at
        FROM search_history
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (user_id,)
    )

    history_records = cursor.fetchall()

    cursor.close()

    return render_template(
        "history.html",
        history=history_records
    )


# =========================================================
# Search Nearby Services
# =========================================================

@app.route(
    "/search",
    methods=["POST"]
)
def search():

    try:

        data = request.get_json()

        if not data:

            return jsonify({
                "error": "No search data received."
            }), 400

        lat = data.get("lat")

        lon = data.get("lon")

        service = data.get("service")

        radius = int(
            data.get(
                "radius",
                5000
            )
        )

        print(
            "SEARCH LAT:",
            lat
        )

        print(
            "SEARCH LON:",
            lon
        )

        print(
            "SERVICE:",
            service
        )

        print(
            "RADIUS:",
            radius
        )

        # -------------------------------------------------
        # Hotel
        # -------------------------------------------------

        if service == "hotel":

            overpass_query = f"""
[out:json][timeout:25];
(
 nwr["tourism"="hotel"](around:{radius},{lat},{lon});
 nwr["tourism"="hostel"](around:{radius},{lat},{lon});
 nwr["tourism"="guest_house"](around:{radius},{lat},{lon});
 nwr["tourism"="motel"](around:{radius},{lat},{lon});
);
out center tags;
"""

        # -------------------------------------------------
        # Cafe / Restaurant
        # -------------------------------------------------

        elif service == "cafe":

            overpass_query = f"""
[out:json][timeout:25];
(
 nwr["amenity"="cafe"](around:{radius},{lat},{lon});
 nwr["amenity"="restaurant"](around:{radius},{lat},{lon});
 nwr["amenity"="fast_food"](around:{radius},{lat},{lon});
);
out center tags;
"""

        # -------------------------------------------------
        # Petrol Pump
        # -------------------------------------------------

        elif service == "fuel":

            overpass_query = f"""
[out:json][timeout:25];
(
 nwr["amenity"="fuel"](around:{radius},{lat},{lon});
);
out center tags;
"""

        # -------------------------------------------------
        # Ice Cream & Candy
        # -------------------------------------------------

        elif service == "ice_cream":

            overpass_query = f"""
[out:json][timeout:25];
(
 nwr["shop"="ice_cream"](around:{radius},{lat},{lon});
 nwr["amenity"="ice_cream"](around:{radius},{lat},{lon});
 nwr["shop"="confectionery"](around:{radius},{lat},{lon});
 nwr["shop"="pastry"](around:{radius},{lat},{lon});
 nwr["shop"="bakery"](around:{radius},{lat},{lon});
);
out center tags;
"""

        # -------------------------------------------------
        # Mall
        # -------------------------------------------------

        elif service == "mall":

            overpass_query = f"""
[out:json][timeout:25];
(
 nwr["shop"="mall"](around:{radius},{lat},{lon});
 nwr["amenity"="marketplace"](around:{radius},{lat},{lon});
 nwr["building"="retail"](around:{radius},{lat},{lon});
);
out center tags;
"""

        # -------------------------------------------------
        # Vehicle Showroom
        # -------------------------------------------------

        elif service == "vehicle_showroom":

            overpass_query = f"""
[out:json][timeout:25];
(
 nwr["shop"="car"](around:{radius},{lat},{lon});
 nwr["shop"="motorcycle"](around:{radius},{lat},{lon});
 nwr["shop"="truck"](around:{radius},{lat},{lon});
 nwr["shop"="tractor"](around:{radius},{lat},{lon});
 nwr["shop"="car_repair"](around:{radius},{lat},{lon});
 nwr["shop"="vehicle"](around:{radius},{lat},{lon});
);
out center tags;
"""

        # -------------------------------------------------
        # Hospital
        # -------------------------------------------------

        elif service == "hospital":

            overpass_query = f"""
[out:json][timeout:25];
(
 nwr["amenity"="hospital"](around:{radius},{lat},{lon});
);
out center tags;
"""

        # -------------------------------------------------
        # Restaurant
        # -------------------------------------------------

        elif service == "restaurant":

            overpass_query = f"""
[out:json][timeout:25];
(
 nwr["amenity"="restaurant"](around:{radius},{lat},{lon});
 nwr["amenity"="fast_food"](around:{radius},{lat},{lon});
);
out center tags;
"""

        # -------------------------------------------------
        # Shop
        # -------------------------------------------------

        elif service == "shop":

            overpass_query = f"""
[out:json][timeout:25];
(
 nwr["shop"](around:{radius},{lat},{lon});
);
out center tags;
"""

        # -------------------------------------------------
        # Car Repair
        # -------------------------------------------------

        elif service == "car_repair":

            overpass_query = f"""
[out:json][timeout:25];
(
 nwr["shop"="car_repair"](around:{radius},{lat},{lon});
);
out center tags;
"""

        # -------------------------------------------------
        # Beauty
        # -------------------------------------------------

        elif service == "beauty":

            overpass_query = f"""
[out:json][timeout:25];
(
 nwr["shop"="beauty"](around:{radius},{lat},{lon});
 nwr["shop"="hairdresser"](around:{radius},{lat},{lon});
);
out center tags;
"""

        # -------------------------------------------------
        # Hostel
        # -------------------------------------------------

        elif service == "hostel":

            overpass_query = f"""
[out:json][timeout:25];
(
 nwr["tourism"="hostel"](around:{radius},{lat},{lon});
);
out center tags;
"""

        # -------------------------------------------------
        # PG / Guest House
        # -------------------------------------------------

        elif service == "pg":

            overpass_query = f"""
[out:json][timeout:25];
(
 nwr["tourism"="guest_house"](around:{radius},{lat},{lon});
 nwr["tourism"="hostel"](around:{radius},{lat},{lon});
);
out center tags;
"""

        # -------------------------------------------------
        # Default Services
        # -------------------------------------------------

        else:

            overpass_query = f"""
[out:json][timeout:25];
(
 nwr["amenity"="{service}"](around:{radius},{lat},{lon});
);
out center tags;
"""

        # =================================================
        # Overpass API Request with Fallback Servers
        # =================================================

        overpass_urls = [
            "https://overpass-api.de/api/interpreter",
            "https://overpass.kumi.systems/api/interpreter",
            "https://overpass.private.coffee/api/interpreter"
        ]

        places = None

        last_error = None

        for url in overpass_urls:

            try:

                print(
                    "TRYING OVERPASS:",
                    url
                )

                response = requests.get(
                    url,
                    params={
                        "data": overpass_query
                    },
                    headers={
                        "User-Agent": "SevaSetu/1.0"
                    },
                    timeout=25
                )

                print(
                    "OVERPASS STATUS:",
                    response.status_code
                )

                print(
                    "OVERPASS RESPONSE:",
                    response.text[:500]
                )

                response.raise_for_status()

                places = response.json()

                print(
                    "OVERPASS SUCCESS:",
                    url
                )

                break

            except requests.exceptions.RequestException as e:

                last_error = e

                print(
                    "OVERPASS FAILED:",
                    url
                )

                print(
                    "ERROR:",
                    e
                )

                continue

            except ValueError as e:

                last_error = e

                print(
                    "OVERPASS JSON ERROR:",
                    url
                )

                print(
                    "ERROR:",
                    e
                )

                continue

        # =================================================
        # All Overpass Servers Failed
        # =================================================

        if places is None:

            print(
                "ALL OVERPASS SERVERS FAILED"
            )

            print(
                "LAST ERROR:",
                last_error
            )

            return jsonify({
                "error":
                "Nearby services are temporarily unavailable. Please try again."
            }), 503

        # =================================================
        # Prepare Results
        # =================================================

        results = []

        for place in places.get(
            "elements",
            []
        ):

            tags = place.get(
                "tags",
                {}
            )

            address = ", ".join(
                filter(
                    None,
                    [
                        tags.get(
                            "addr:housenumber"
                        ),

                        tags.get(
                            "addr:street"
                        ),

                        tags.get(
                            "addr:city"
                        ),

                        tags.get(
                            "addr:state"
                        )
                    ]
                )
            )

            if address == "":

                address = (
                    "Address Not Available"
                )

            place_lat = (
                place.get("lat")
                or place.get(
                    "center",
                    {}
                ).get("lat")
            )

            place_lon = (
                place.get("lon")
                or place.get(
                    "center",
                    {}
                ).get("lon")
            )

            if place_lat is None or place_lon is None:

                continue

            results.append({

                "name": tags.get(
                    "name",
                    "Unknown"
                ),

                "lat": place_lat,

                "lon": place_lon,

                "address": address

            })

        print(
            "TOTAL RESULTS:",
            len(results)
        )

        return jsonify(results)

    except Exception as e:

        print(
            "SEARCH ERROR:",
            e
        )

        return jsonify({
            "error": (
                "Something went wrong "
                "while searching."
            )
        }), 500


# =========================================================
# Run Application
# =========================================================

if __name__ == "__main__":

    init_db()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )