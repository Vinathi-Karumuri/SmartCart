from flask import Flask, render_template, request, redirect, session, flash, url_for, jsonify
from flask_mail import Mail, Message
import sqlite3
import bcrypt  
import random
import config
import os
from werkzeug.utils import secure_filename
import secrets
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash
import traceback
import razorpay
from flask import make_response
from utils.pdf_generator import generate_pdf

# Flask app initialization:
razorpay_client = razorpay.Client(
    auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET)
)

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# ---------------- EMAIL CONFIGURATION ----------------
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD
ADMIN_UPLOAD_FOLDER = 'static/uploads/admin_profiles'
app.config['ADMIN_UPLOAD_FOLDER'] = ADMIN_UPLOAD_FOLDER
USER_UPLOAD_FOLDER = 'static/uploads/user_profiles'
app.config['USER_UPLOAD_FOLDER'] = USER_UPLOAD_FOLDER

mail = Mail(app)

# ---------------- DB CONNECTION FUNCTION --------------
def get_db_connection():
    conn = sqlite3.connect("smartcart.db")
    conn.row_factory = sqlite3.Row
    return conn

# -----------------Home------------------------
@app.route('/')
def Home():
    return render_template("home.html", navbar_type="public")

# --------------------About--------------------
@app.route('/about')
def about():
    return render_template("about.html", navbar_type="public")

# --------------------- Contact ------------------
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        # get form data
        name = request.form['name']
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']

        flash("Message sent successfully!", "success")

        return redirect('/contact')

    return render_template("contact.html", navbar_type="public")

# ----------- Login Choice ------------
@app.route('/login')
def common_login():
    return render_template('auth/login_choice.html', navbar_type="public")

# ---------- Register choice -----------
@app.route('/register')
def common_register():
    return render_template('auth/register_choice.html', navbar_type="public")

# ---------------- ADMIN SIGNUP ----------------
@app.route('/admin-signup', methods=['GET', 'POST'])
def admin_signup():

    if request.method == "GET":
        return render_template("admin/admin_signup.html", navbar_type="public")

    name = request.form['name']
    email = request.form['email']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT admin_id FROM admin WHERE email=?", (email,))
    existing_admin = cursor.fetchone()
    cursor.close()
    conn.close()

    if existing_admin:
        flash("This email is already registered. Please login instead.", "danger")
        return redirect('/admin-signup')

    session['signup_name'] = name
    session['signup_email'] = email

    otp = random.randint(100000, 999999)
    session['otp'] = otp

    message = Message(
        subject="SmartCart Admin OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = f"Your OTP for SmartCart Admin Registration is: {otp}"
    mail.send(message)

    flash("OTP sent to your email!", "success")
    return redirect('/verify-otp')

# ---------------- VERIFY OTP ----------------
@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():

    if request.method == 'GET':
        return render_template("admin/verify_otp.html", navbar_type="public")

    user_otp = request.form['otp']
    password = request.form['password']

    if str(session.get('otp')) != str(user_otp):
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/verify-otp')

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO admin (name, email, password) VALUES (?, ?, ?)",
        (session['signup_name'], session['signup_email'], hashed_password)
    )
    conn.commit()
    cursor.close()
    conn.close()

    session.clear()

    flash("Admin Registered Successfully!", "success")
    return redirect('/admin-login')

# ---------------- ADMIN LOGIN ----------------
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():

    if request.method == 'GET':
        return render_template("admin/admin_login.html", navbar_type="public")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin WHERE email=?", (email,))
    admin = cursor.fetchone()
    cursor.close()
    conn.close()

    if admin is None:
        flash("Email not found! Please register first.", "danger")
        return redirect('/admin-login')

    if not bcrypt.checkpw(password.encode('utf-8'), admin['password']):
        flash("Incorrect password!", "danger")
        return redirect('/admin-login')

    session['admin_id'] = admin['admin_id']
    session['admin_name'] = admin['name']

    flash("Login Successful!", "success")
    return redirect('/admin-dashboard')

# ---------------Admin Forget password---------------
@app.route('/admin-forgot-password', methods=['GET', 'POST'])
def admin_forgot_password():

    if request.method == 'POST':
        email = request.form['email']

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM admin WHERE email=?", (email,))
        admin = cursor.fetchone()

        if not admin:
            flash("Please enter valid registered email!", "danger")
            return redirect('/admin-forgot-password')

        token = secrets.token_urlsafe(32)
        expiry = datetime.utcnow() + timedelta(minutes=15)

        cursor.execute(
            "UPDATE admin SET reset_token=?, token_expiry=? WHERE email=?",
            (token, expiry, email)
        )
        conn.commit()

        reset_link = url_for('admin_reset_password', token=token, _external=True)

        msg = Message(
            subject="Reset Your Admin Password",
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )
        msg.body = f"Click the link to reset password:\n{reset_link}"
        mail.send(msg)

        flash("Reset link sent to your email!", "success")
        return redirect('/admin-login')

    return render_template('admin/forgot_password.html', navbar_type="public")

# ------------Admin reset password------------
@app.route('/admin-reset-password/<token>', methods=['GET', 'POST'])
def admin_reset_password(token):

    conn = get_db_connection()
    cursor = conn.cursor()

    # 1️⃣ Find admin by token
    cursor.execute(
        "SELECT * FROM admin WHERE reset_token=?",
        (token,)
    )
    admin = cursor.fetchone()

    # 2️⃣ Invalid or expired token
    if not admin or not admin['token_expiry']:
        flash("Invalid or expired reset link!", "danger")
        return redirect('/admin-login')

    token_expiry = datetime.fromisoformat(admin['token_expiry'])

    if token_expiry < datetime.utcnow():
        flash("Reset link expired!", "danger")
        return redirect('/admin-login')

    # 3️⃣ If form submitted → update password
    if request.method == 'POST':
        new_password = request.form['password']

        hashed_password = bcrypt.hashpw(
            new_password.encode('utf-8'),
            bcrypt.gensalt()
        )

        cursor.execute(
            """
            UPDATE admin
            SET password=?, reset_token=NULL, token_expiry=NULL
            WHERE admin_id=?
            """,
            (hashed_password, admin['admin_id'],token)
        )

        conn.commit()
        cursor.close()
        conn.close()

        flash("Password updated successfully. Please login!", "success")
        return redirect('/admin-login')

    return render_template(
        "admin/reset_password.html",
        navbar_type="public"
    )

# ---------------- ADMIN DASHBOARD ----------------
@app.route('/admin-dashboard')
def admin_dashboard():

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    search = request.args.get('search', '')
    category = request.args.get('category', '')

    admin_id = session['admin_id']  

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT DISTINCT category FROM products WHERE admin_id = ?",
        (admin_id,)
    )
    categories = cursor.fetchall()

    query = "SELECT * FROM products WHERE admin_id = ?"
    params = [admin_id]

    if search:
        query += " AND name LIKE ?"
        params.append("%" + search + "%")

    if category:
        query += " AND category = ?"
        params.append(category)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "admin/dashboard.html",
        navbar_type="admin",
        admin_name=session['admin_name'],
        products=products,
        categories=categories
    )

# ---------------- ADMIN LOGOUT ----------------
@app.route('/admin-logout')
def admin_logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect('/admin-login')

UPLOAD_FOLDER = 'static/uploads/product_images'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ---------------- ADD PRODUCT ---------------
@app.route('/admin/add-item', methods=['GET', 'POST'])
def add_item():

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    if request.method == 'GET':
        return render_template("admin/add_item.html", navbar_type="admin")

    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']
    image_file = request.files['image']

    filename = secure_filename(image_file.filename)
    image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO products (name, description, category, price, image, admin_id) VALUES (?,?,?,?,?,?)",
        (name, description, category, price, filename, admin_id)
    )

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product added successfully!", "success")
    return redirect('/admin/add-item')

# ---------------DISPLAY ALL PRODUCTS (Admin)--------------
@app.route('/admin/item-list')
def item_list():

    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id'] 

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT DISTINCT category FROM products WHERE admin_id = ?",
        (admin_id,)
    )
    categories = cursor.fetchall()

    query = "SELECT * FROM products WHERE admin_id = ?"
    params = [admin_id]

    if search:
        query += " AND name LIKE ?"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("admin/item_list.html",products=products,categories=categories,navbar_type="admin")

# -------------VIEW SINGLE PRODUCT DETAILS---------------
@app.route('/admin/view-item/<int:item_id>')
def view_item(item_id):

    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']  

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM products WHERE product_id = ? AND admin_id = ?",
        (item_id, admin_id)
    )
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found or unauthorized access!", "danger")
        return redirect('/admin-dashboard')

    return render_template("admin/view_item.html",product=product,navbar_type="admin")

# ---------- SHOW UPDATE FORM ----------
@app.route('/admin/update-item/<int:item_id>', methods=['GET'])
def update_item_page(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM products WHERE product_id=? AND admin_id=?",
        (item_id, admin_id)
    )
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found or unauthorized access!", "danger")
        return redirect('/admin/item-list')

    return render_template(
        "admin/update_item.html",
        product=product,
        navbar_type="admin"
    )

# ---------- UPDATE PRODUCT ----------
@app.route('/admin/update-item/<int:item_id>', methods=['POST'])
def update_item(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']
    new_image = request.files.get('image')

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Fetch product
        cursor.execute(
            "SELECT * FROM products WHERE product_id=? AND admin_id=?",
            (item_id, admin_id)
        )
        product = cursor.fetchone()

        if not product:
            flash("Product not found or unauthorized access!", "danger")
            return redirect('/admin/item-list')

        old_image = product['image']

        # Image replace
        if new_image and new_image.filename:
            filename = secure_filename(new_image.filename)
            new_image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            if old_image:
                old_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image)
                if os.path.exists(old_path):
                    os.remove(old_path)
        else:
            filename = old_image

        # Update DB
        cursor.execute("""
            UPDATE products
            SET name=?, description=?, category=?, price=?, image=?
            WHERE product_id=? AND admin_id=?
        """, (name, description, category, price, filename, item_id, admin_id))

        conn.commit()
        flash("Product updated successfully!", "success")

    except sqlite3.IntegrityError:
        conn.rollback()
        flash("Update failed due to database constraint.", "danger")

    finally:
        cursor.close()
        conn.close()

    return redirect('/admin/item-list')

# --------------- Delete Item from Products-------------
@app.route('/admin/delete-item/<int:item_id>')
def delete_item(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Fetch product
        cursor.execute(
            "SELECT image FROM products WHERE product_id=? AND admin_id=?",
            (item_id, admin_id)
        )
        product = cursor.fetchone()

        if not product:
            flash("Product not found or unauthorized access!", "danger")
            return redirect('/admin/item-list')

        image_name = product['image']

        # Delete product
        cursor.execute(
            "DELETE FROM products WHERE product_id=? AND admin_id=?",
            (item_id, admin_id)
        )
        conn.commit()

        # Delete image file
        if image_name:
            img_path = os.path.join(app.config['UPLOAD_FOLDER'], image_name)
            if os.path.exists(img_path):
                os.remove(img_path)

        flash("Product deleted successfully!", "success")

    except sqlite3.IntegrityError:
        conn.rollback()
        flash(
            "Cannot delete this product because it is already used in orders.",
            "danger"
        )

    finally:
        cursor.close()
        conn.close()

    return redirect('/admin/item-list')

# ---------------- SHOW ADMIN PROFILE DATA ------------------
@app.route('/admin/profile', methods=['GET'])
def admin_profile():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template("admin/admin_profile.html", admin=admin, navbar_type="admin")

# ----------- UPDATE ADMIN PROFILE (NAME, EMAIL, PASSWORD, IMAGE)----------
@app.route('/admin/profile', methods=['POST'])
def admin_profile_update():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    # 1️⃣ Get form data
    name = request.form['name']
    email = request.form['email']
    new_password = request.form['password']
    new_image = request.files['profile_image']

    conn = get_db_connection()
    cursor = conn.cursor()

    # 2️⃣ Fetch old admin data
    cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
    admin = cursor.fetchone()

    old_image_name = admin['profile_image']

    # 3️⃣ Update password only if entered
    if new_password:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    else:
        hashed_password = admin['password']  # keep old password

    # 4️⃣ Process new profile image if uploaded
    if new_image and new_image.filename != "":
        
        from werkzeug.utils import secure_filename
        new_filename = secure_filename(new_image.filename)

        # Save new image
        image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], new_filename)
        new_image.save(image_path)

        # Delete old image
        if old_image_name:
            old_image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    # 5️⃣ Update database
    cursor.execute("""UPDATE admin SET name=?, email=?, password=?, profile_image=? WHERE admin_id=?""", (name, email, hashed_password, final_image_name, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    # Update session name for UI consistency
    session['admin_name'] = name  
    session['admin_email'] = email

    flash("Profile updated successfully!", "success")
    return redirect('/admin/profile')

# ------------ USER REGISTRATION----------
@app.route('/user-register', methods=['GET', 'POST'])
def user_register():

    if request.method == 'GET':
        return render_template("user/user_register.html", navbar_type="public")

    name = request.form['name']
    email = request.form['email']
    password = request.form['password']

    # Check if user already exists
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        flash("Email already registered! Please login.", "danger")
        return redirect('/user-register')

    # Hash password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insert new user
    cursor.execute(
        "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
        (name, email, hashed_password)
    )
    conn.commit()

    cursor.close()
    conn.close()

    flash("Registration successful! Please login.", "success")
    return redirect('/user-login')

# --------------USER LOGIN----------------
@app.route('/user-login', methods=['GET', 'POST'])
def user_login():

    if request.method == 'GET':
        return render_template("user/user_login.html", navbar_type="public")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        flash("Email not found! Please register.", "danger")
        return redirect('/user-login')

    # Verify password
    if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        flash("Incorrect password!", "danger")
        return redirect('/user-login')

    # Create user session
    session['user_id'] = user['user_id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']
    flash("Login successful!", "success")
    return redirect('/user-dashboard')

# ------------ USER FORGOT PASSWORD ------------
@app.route('/user-forgot-password', methods=['GET', 'POST'])
def user_forgot_password():

    if request.method == 'POST':
        email = request.form['email']

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cursor.fetchone()

        if not user:
            flash("Email not registered!", "danger")
            return redirect('/user-forgot-password')

        token = secrets.token_urlsafe(32)
        expiry = datetime.utcnow() + timedelta(minutes=15)

        cursor.execute(
            "UPDATE users SET reset_token=?, token_expiry=? WHERE email=?",
            (token, expiry, email)
        )
        conn.commit()

        reset_link = url_for('user_reset_password', token=token, _external=True)

        msg = Message(
            subject="Reset Your SmartCart Password",
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )
        msg.body = f"Click here to reset your password:\n{reset_link}"
        mail.send(msg)

        cursor.close()
        conn.close()

        flash("Password reset link sent to your email!", "success")
        return redirect('/user-login')

    return render_template(
        "user/user_forgot_password.html",
        navbar_type="public"
    )

# ------------ USER RESET PASSWORD ------------
@app.route('/user-reset-password/<token>', methods=['GET', 'POST'])
def user_reset_password(token):

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE reset_token=?",
        (token,)
    )
    user = cursor.fetchone()

    if not user or not user['token_expiry']:
        flash("Invalid or expired reset link!", "danger")
        return redirect('/user-login')

    token_expiry = datetime.fromisoformat(user['token_expiry'])

    if token_expiry < datetime.utcnow():
        flash("Reset link expired!", "danger")
        return redirect('/user-login')

    if request.method == 'POST':
        new_password = request.form['password']
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

        cursor.execute(
            """
            UPDATE users
            SET password=?, reset_token=NULL, token_expiry=NULL
            WHERE user_id=? AND reset_token=?
            """,
            (hashed_password, user['user_id'],token)
        )
        conn.commit()
        cursor.close()
        conn.close()

        flash("Password updated successfully!", "success")
        return redirect('/user-login')

    return render_template(
        "user/user_reset_password.html",
        navbar_type="public"
    )

# ------------USER DASHBOARD--------------
@app.route('/user-dashboard')
def user_dashboard():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Categories
    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    # Products
    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE ?"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "user/user_home.html",   
        user_name=session['user_name'],
        products=products,       
        categories=categories,  
        navbar_type="user"
    )

# -----------USER LOGOUT------------
@app.route('/user-logout')
def user_logout():
    
    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_email', None)

    flash("Logged out successfully!", "success")
    return redirect('/user-login')

# ------------USER PRODUCT LISTING (SEARCH + FILTER)------------
@app.route('/user/products')
def user_products():

    if 'user_id' not in session:
        flash("Please login to view products!", "danger")
        return redirect('/user-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE ?"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/user_products.html",products=products,categories=categories, navbar_type="user")

# ---------------USER PRODUCT DETAILS PAGE-------------
@app.route('/user/product/<int:product_id>')
def user_product_details(product_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM products WHERE product_id = ?", (product_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/user/products')

    return render_template("user/product_details.html", product=product, navbar_type="user")

# -------------ADD ITEM TO CART----------------
@app.route('/user/add-to-cart/<int:product_id>')
def add_to_cart(product_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check product exists
    cursor.execute("SELECT * FROM products WHERE product_id=?", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash("Product not found.", "danger")
        return redirect(request.referrer)

    # Check if product already in cart
    cursor.execute("""
        SELECT * FROM cart 
        WHERE user_id=? AND product_id=?
    """, (user_id, product_id))
    existing = cursor.fetchone()

    if existing:
        cursor.execute("""
            UPDATE cart 
            SET quantity = quantity + 1 
            WHERE user_id=? AND product_id=?
        """, (user_id, product_id))
    else:
        cursor.execute("""
            INSERT INTO cart (user_id, product_id, quantity)
            VALUES (?, ?, 1)
        """, (user_id, product_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Item added to cart!", "success")
    return redirect(request.referrer)

# --------------VIEW CART PAGE-----------------
@app.route('/user/cart')
def view_cart():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            c.id,
            c.product_id,
            p.name,
            p.price,
            p.image,
            c.quantity
        FROM cart c
        JOIN products p ON c.product_id = p.product_id
        WHERE c.user_id = ?
    """, (user_id,))

    cart_items = cursor.fetchall()

    cursor.close()
    conn.close()

    grand_total = sum(
        item['price'] * item['quantity'] for item in cart_items
    )

    return render_template(
        "user/cart.html",
        cart=cart_items,
        grand_total=grand_total,
        navbar_type="user"
    )

# ------------INCREASE QUANTITY-----------------
@app.route('/user/cart/increase/<int:product_id>')
def increase_quantity(product_id):

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE cart 
        SET quantity = quantity + 1
        WHERE user_id=? AND product_id=?
    """, (user_id, product_id))

    conn.commit()
    cursor.close()
    conn.close()

    return redirect('/user/cart')

# ---------------DECREASE QUANTITY------------------
@app.route('/user/cart/decrease/<int:product_id>')
def decrease_quantity(product_id):

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE cart 
        SET quantity = quantity - 1
        WHERE user_id=? AND product_id=?
    """, (user_id, product_id))

    cursor.execute("""
        DELETE FROM cart 
        WHERE user_id=? AND product_id=? AND quantity <= 0
    """, (user_id, product_id))

    conn.commit()
    cursor.close()
    conn.close()

    return redirect('/user/cart')

# ---------------REMOVE ITEM-----------------
@app.route('/user/cart/remove/<int:product_id>')
def remove_from_cart(product_id):

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM cart 
        WHERE user_id=? AND product_id=?
    """, (user_id, product_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Item removed!", "success")
    return redirect('/user/cart')

# ----------------- SHOW USER PROFILE DATA------------------
@app.route('/user/profile', methods=['GET'])
def user_profile():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template("user/user_profile.html", user=user, navbar_type="user")

# -------- UPDATE USER PROFILE (NAME, EMAIL, PASSWORD, IMAGE)----------
@app.route('/user/profile', methods=['POST'])
def user_profile_update():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    # 1️⃣ Get form data
    name = request.form['name']
    email = request.form['email']
    new_password = request.form['password']
    new_image = request.files['profile_image']

    conn = get_db_connection()
    cursor = conn.cursor()

    # 2️⃣ Fetch old user data
    cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
    user = cursor.fetchone()

    old_image_name = user['profile_image']

    # 3️⃣ Update password only if entered
    if new_password:
        hashed_password = bcrypt.hashpw(
            new_password.encode('utf-8'),
            bcrypt.gensalt()
        )
    else:
        hashed_password = user['password']  # keep old password

    # 4️⃣ Process new profile image if uploaded
    if new_image and new_image.filename != "":

        from werkzeug.utils import secure_filename
        new_filename = secure_filename(new_image.filename)

        # Save new image
        image_path = os.path.join(app.config['USER_UPLOAD_FOLDER'], new_filename)
        new_image.save(image_path)

        # Delete old image
        if old_image_name:
            old_image_path = os.path.join(app.config['USER_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    # 5️⃣ Update database
    cursor.execute("""UPDATE users SET name=?, email=?, password=?, profile_image=? WHERE user_id=?""", (name, email, hashed_password, final_image_name, user_id))

    conn.commit()
    cursor.close()
    conn.close()

    # Update session data
    session['user_name'] = name
    session['user_email'] = email

    flash("Profile updated successfully!", "success")
    return redirect('/user/profile')

# ------------ Route: ADD ADDRESS (GET + POST) -------------
@app.route('/user/add-address', methods=['GET', 'POST'])
def add_address():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    if request.method == 'GET':
        return render_template("user/add_address.html", navbar_type="user")

    # ---------- POST ----------
    user_id = session['user_id']

    name = request.form['name']
    mobile = request.form['mobile']
    address = request.form['address']
    city = request.form['city']
    state = request.form['state']
    pincode = request.form['pincode']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO user_addresses 
        (user_id, name, mobile, address, city, state, pincode)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (user_id, name, mobile, address, city, state, pincode))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Address added successfully!", "success")
    return redirect('/user/select-address')

# ---------- CREATE RAZORPAY ORDER------------
@app.route('/user/pay')
def user_pay():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    if 'selected_address_id' not in session:
        flash("Please select delivery address first.", "danger")
        return redirect('/user/select-address')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT p.product_id, p.name, p.price, c.quantity
        FROM cart c
        JOIN products p ON c.product_id = p.product_id
        WHERE c.user_id = ?
    """, (user_id,))

    cart_items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not cart_items:
        flash("Your cart is empty!", "danger")
        return redirect('/user/products')

    total_amount = sum(
        item['price'] * item['quantity']
        for item in cart_items
    )

    razorpay_amount = int(total_amount * 100)

    razorpay_order = razorpay_client.order.create({
        "amount": razorpay_amount,
        "currency": "INR",
        "payment_capture": "1"
    })

    session['razorpay_order_id'] = razorpay_order['id']

    return render_template(
        "user/payment.html",
        amount=total_amount,
        key_id=config.RAZORPAY_KEY_ID,
        order_id=razorpay_order['id'], navbar_type="user"
    )

# ----------- Select Address --------
@app.route('/user/select-address', methods=['GET'])
def select_address():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM user_addresses WHERE user_id=?",
        (user_id,)
    )
    addresses = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('user/select_address.html',addresses=addresses, navbar_type="user")

# ------------  Confirm Address --------
@app.route('/user/confirm-address', methods=['POST'])
def confirm_address():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    address_id = request.form.get('address_id')

    if not address_id:
        flash("Please select an address.", "danger")
        return redirect('/user/select-address')

    # store address in session
    session['selected_address_id'] = address_id

    return redirect('/user/pay')

# ----------- Verify Payment and Store Order-----------
@app.route('/verify-payment', methods=['POST'])
def verify_payment():

    if 'user_id' not in session:
        flash("Please login to complete the payment.", "danger")
        return redirect('/user-login')

    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')

    if not (razorpay_payment_id and razorpay_order_id and razorpay_signature):
        flash("Payment verification failed (missing data).", "danger")
        return redirect('/user/cart')

    payload = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_signature': razorpay_signature
    }

    try:
        razorpay_client.utility.verify_payment_signature(payload)
    except Exception as e:
        app.logger.error("Razorpay signature verification failed: ?", str(e))
        flash("Payment verification failed.", "danger")
        return redirect('/user/cart')

    # ---------- AFTER PAYMENT VERIFIED ----------
    user_id = session['user_id']
    address_id = session.get('selected_address_id')

    if not address_id:
        flash("Delivery address not selected.", "danger")
        return redirect('/user/cart')

    conn = get_db_connection()
    cursor = conn.cursor()

    # FETCH CART FROM DB
    cursor.execute("""
        SELECT p.product_id, p.name, p.price, c.quantity
        FROM cart c
        JOIN products p ON c.product_id = p.product_id
        WHERE c.user_id = ?
    """, (user_id,))

    cart_items = cursor.fetchall()

    if not cart_items:
        cursor.close()
        conn.close()
        flash("Cart is empty.", "danger")
        return redirect('/user/products')

    total_amount = sum(
        item['price'] * item['quantity']
        for item in cart_items
    )

    try:
        # 1️⃣ Insert order
        cursor.execute("""
            INSERT INTO orders 
            (user_id, address_id, razorpay_order_id, razorpay_payment_id, amount, payment_status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            address_id,
            razorpay_order_id,
            razorpay_payment_id,
            total_amount,
            'paid'
        ))

        order_db_id = cursor.lastrowid

        # 2️⃣ Insert order items
        for item in cart_items:
            cursor.execute("""
                INSERT INTO order_items
                (order_id, product_id, product_name, quantity, price)
                VALUES (?, ?, ?, ?, ?)
            """, (
                order_db_id,
                item['product_id'],
                item['name'],
                item['quantity'],
                item['price']
            ))

        # 3️⃣ CLEAR CART FROM DB
        cursor.execute("DELETE FROM cart WHERE user_id = ?", (user_id,))

        conn.commit()

        # 4️⃣ Clear payment-related session data
        session.pop('razorpay_order_id', None)
        session.pop('selected_address_id', None)

        flash("Payment successful! Order placed.", "success")
        return redirect(f"/user/order-success/{order_db_id}")

    except Exception as e:
        conn.rollback()
        app.logger.error("Order storage failed: ?", str(e))
        flash("There was an error saving your order. Contact support.", "danger")
        return redirect('/user/cart')

    finally:
        cursor.close()
        conn.close()

# ---------- PAYMENT FAILURE----------
@app.route('/payment-failure')
def payment_failure():

    error_reason = request.args.get('reason', 'Payment was cancelled or failed.')

    flash("Payment failed. Please try again.", "danger")

    return render_template("user/payment_failure.html",reason=error_reason, navbar_type="user")

# ----------- Order Success (WITH ADDRESS)-----------
@app.route('/user/order-success/<int:order_db_id>')
def order_success(order_db_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch order + delivery address
    cursor.execute("""
        SELECT 
            o.*,
            a.name AS address_name,
            a.mobile,
            a.address,
            a.city,
            a.state,
            a.pincode
        FROM orders o
        JOIN user_addresses a ON o.address_id = a.address_id
        WHERE o.order_id = ? AND o.user_id = ?
    """, (order_db_id, user_id))

    order = cursor.fetchone()

    if not order:
        cursor.close()
        conn.close()
        flash("Order not found.", "danger")
        return redirect('/user/products')

    # Fetch order items
    cursor.execute("""
        SELECT product_name, quantity, price
        FROM order_items
        WHERE order_id = ?
    """, (order_db_id,))

    items = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/order_success.html",order=order,items=items, navbar_type="user")

# ----------- View past orders------------
@app.route('/user/my-orders')
def my_orders():
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC", (session['user_id'],))
    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/my_orders.html", orders=orders, navbar_type="user")

# ------------- GENERATE INVOICE PDF (WITH ADDRESS)--------------
@app.route("/user/download-invoice/<int:order_id>")
def download_invoice(order_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch order + address
    cursor.execute("""
        SELECT 
            o.*,
            a.name AS address_name,
            a.mobile,
            a.address,
            a.city,
            a.state,
            a.pincode
        FROM orders o
        JOIN user_addresses a ON o.address_id = a.address_id
        WHERE o.order_id = ? AND o.user_id = ?
    """, (order_id, session['user_id']))

    order = cursor.fetchone()

    # Fetch items
    cursor.execute("""
        SELECT product_name, quantity, price
        FROM order_items
        WHERE order_id = ?
    """, (order_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/my-orders')

    # Render invoice HTML
    html = render_template("user/invoice.html",order=order,items=items, navbar_type="user")

    pdf = generate_pdf(html)
    if not pdf:
        flash("Error generating PDF", "danger")
        return redirect('/user/my-orders')

    response = make_response(pdf.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f"attachment; filename=invoice_{order_id}.pdf"

    return response

@app.context_processor
def inject_cart_count():
    if 'user_id' not in session:
        return dict(cart_count=0)

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COALESCE(SUM(quantity), 0)
        FROM cart
        WHERE user_id = ?
    """, (user_id,))

    count = cursor.fetchone()[0]

    cursor.close()
    conn.close()

    return dict(cart_count=count)

if __name__ == '__main__':
    app.run(debug=True)