from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user

app = Flask(__name__)


login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return get_user_by_id(user_id)

class User(UserMixin):
    def __init__(self, id, username, password, role):
        self.id = id
        self.username = username
        self.password = password
        self.role = role

# Database operations module
def db_execute(query, params=(), fetch_one=False, fetch_all=False):
    """Execute a database query with optional fetching."""
    try:
        conn = sqlite3.connect('ticket.db')
        c = conn.cursor()
        c.execute(query, params)
        if fetch_one:
            result = c.fetchone()
        elif fetch_all:
            result = c.fetchall()
        else:
            result = None
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        result = None
    finally:
        conn.close()
    return result

# Helper Functions
def create_db():
    """Create necessary database tables."""
    db_execute("DROP TABLE IF EXISTS tickets")
    db_execute('''CREATE TABLE IF NOT EXISTS tickets (
                    ID INTEGER PRIMARY KEY AUTOINCREMENT,
                    description TEXT NOT NULL,
                    topic TEXT NOT NULL,
                    status TEXT DEFAULT 'Open'
                )''')
    db_execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    role TEXT DEFAULT 'user'
                )''')

def get_user_by_username(username):
    query = "SELECT * FROM users WHERE username = ?"
    user = db_execute(query, (username,), fetch_one=True)
    if user:
        return User(id=user[0], username=user[1], password=user[2], role=user[3])
    return None

def get_user_by_id(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    user = db_execute(query, (user_id,), fetch_one=True)
    if user:
        return User(id=user[0], username=user[1], password=user[2], role=user[3])
    return None

def add_user(username, password, role="user"):
    hashed_password = generate_password_hash(password)
    query = "INSERT INTO users (username, password, role) VALUES (?, ?, ?)"
    db_execute(query, (username, hashed_password, role))

def get_tickets():
    query = "SELECT * FROM tickets"
    return db_execute(query, fetch_all=True)

def add_ticket_to_db(description, topic, status="Open"):
    query = "INSERT INTO tickets (description, topic, status) VALUES (?, ?, ?)"
    db_execute(query, (description, topic, status))

# Routes
@app.route('/')
@login_required
def index():
    tickets = get_tickets()
    return render_template('index.html', tickets=tickets)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', 'user')

        if not username or not password:
            flash('Username and password are required!', 'error')
        elif get_user_by_username(username):
            flash('Username already taken!', 'error')
        else:
            add_user(username, password, role)
            user = get_user_by_username(username)
            login_user(user)
            flash('User registered and logged in successfully!', 'success')
            return redirect(url_for('index'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            flash('Username and password are required!', 'error')
        else:
            user = get_user_by_username(username)
            if user and check_password_hash(user.password, password):
                login_user(user)
                flash('Logged in successfully!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Invalid credentials!', 'error')

    return render_template('login.html')

@app.route('/add_ticket', methods=['POST'])
@login_required
def add_ticket():
    description = request.form.get('description', '').strip()
    topic = request.form.get('topic', '').strip()

    if not description or not topic:
        flash('Description and topic are required!', 'error')
    else:
        add_ticket_to_db(description, topic)
        flash('Ticket added successfully!', 'success')

    return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('You do not have access to this page.', 'error')
        return redirect(url_for('index'))  # Redirect non-admin users to the homepage
    tickets = get_tickets()  # Fetch all tickets for admin
    return render_template('admin_dashboard.html', tickets=tickets)

@app.route('/update_ticket_status/<int:ticket_id>/<status>')
@login_required
def update_ticket_status(ticket_id, status):
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('index'))

    # Update ticket status in the database
    query = "UPDATE tickets SET status = ? WHERE ID = ?"
    db_execute(query, (status, ticket_id))
    flash(f'Ticket status updated to {status}!', 'success')

    return redirect(url_for('admin_dashboard'))

# Manually create admin user (call this function once to create the admin)
def create_admin():
    admin = get_user_by_username('admin')
    if not admin:
        add_user('admin', 'adminpassword', role='admin')

if __name__ == "__main__":
    create_db()
    create_admin()  # Create the default admin user
    app.run(debug=True)
