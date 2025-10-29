"""
Custom Vulnerable Web Application
Purpose: Controlled test environment for CPG-based security analysis

This application intentionally contains multiple vulnerability types:
1. SQL Injection (login, user search)
2. XSS (search, profile)
3. IDOR (user profile access)
4. Missing Authorization (admin endpoints)
5. Business Logic Flaw (price manipulation in checkout)
"""

from flask import Flask, request, jsonify, render_template_string, session
import sqlite3
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = 'insecure-secret-key-for-testing'

# Initialize database
def init_db():
    conn = sqlite3.connect('/tmp/vulnerable_app.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, 
                  email TEXT, role TEXT, balance REAL)''')
    
    # Products table
    c.execute('''CREATE TABLE IF NOT EXISTS products
                 (id INTEGER PRIMARY KEY, name TEXT, price REAL, stock INTEGER)''')
    
    # Orders table
    c.execute('''CREATE TABLE IF NOT EXISTS orders
                 (id INTEGER PRIMARY KEY, user_id INTEGER, total REAL, 
                  items TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Insert test data
    c.execute("DELETE FROM users")
    c.execute("INSERT INTO users VALUES (1, 'admin', 'admin123', 'admin@test.com', 'admin', 10000.00)")
    c.execute("INSERT INTO users VALUES (2, 'alice', 'alice123', 'alice@test.com', 'user', 500.00)")
    c.execute("INSERT INTO users VALUES (3, 'bob', 'bob123', 'bob@test.com', 'user', 250.00)")
    
    c.execute("DELETE FROM products")
    c.execute("INSERT INTO products VALUES (1, 'Laptop', 1000.00, 10)")
    c.execute("INSERT INTO products VALUES (2, 'Mouse', 25.00, 50)")
    c.execute("INSERT INTO products VALUES (3, 'Keyboard', 75.00, 30)")
    
    conn.commit()
    conn.close()

init_db()


# ============================================================================
# VULNERABILITY 1: SQL Injection (Login)
# ============================================================================
@app.route('/api/login', methods=['POST'])
def login():
    """
    SQL Injection vulnerability - user input directly in query
    
    Vulnerable Query: SELECT * FROM users WHERE username='$username' AND password='$password'
    Exploit: username = admin' OR '1'='1' --
    """
    username = request.json.get('username', '')
    password = request.json.get('password', '')
    
    # VULNERABLE: String concatenation in SQL query
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    
    conn = sqlite3.connect('/tmp/vulnerable_app.db')
    c = conn.cursor()
    c.execute(query)  # Direct execution without parameterization
    user = c.fetchone()
    conn.close()
    
    if user:
        session['user_id'] = user[0]
        session['username'] = user[1]
        session['role'] = user[4]
        return jsonify({
            'success': True,
            'message': f'Welcome {user[1]}!',
            'user_id': user[0],
            'role': user[4]
        })
    else:
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401


# ============================================================================
# VULNERABILITY 2: XSS (Reflected Cross-Site Scripting)
# ============================================================================
@app.route('/api/search', methods=['GET'])
def search():
    """
    XSS vulnerability - user input reflected without escaping
    
    Vulnerable: Returns user input directly in HTML
    Exploit: /api/search?q=<script>alert(document.cookie)</script>
    """
    query = request.args.get('q', '')
    
    conn = sqlite3.connect('/tmp/vulnerable_app.db')
    c = conn.cursor()
    # Safe query (parameterized)
    c.execute("SELECT * FROM products WHERE name LIKE ?", (f'%{query}%',))
    results = c.fetchall()
    conn.close()
    
    # VULNERABLE: Reflects user input without escaping
    html = f"""
    <html>
    <body>
        <h1>Search Results for: {query}</h1>
        <ul>
            {''.join([f'<li>{r[1]} - ${r[2]}</li>' for r in results])}
        </ul>
    </body>
    </html>
    """
    
    return html


# ============================================================================
# VULNERABILITY 3: IDOR (Insecure Direct Object Reference)
# ============================================================================
@app.route('/api/user/<int:user_id>/profile', methods=['GET'])
def get_profile(user_id):
    """
    IDOR vulnerability - no authorization check
    
    Vulnerable: Any user can access any profile by changing user_id
    Exploit: User 2 accesses /api/user/1/profile (admin's profile)
    """
    # VULNERABLE: No check if current user == user_id
    # Missing: if session.get('user_id') != user_id: return 403
    
    conn = sqlite3.connect('/tmp/vulnerable_app.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    conn.close()
    
    if user:
        return jsonify({
            'id': user[0],
            'username': user[1],
            'email': user[3],
            'role': user[4],
            'balance': user[5]
        })
    else:
        return jsonify({'error': 'User not found'}), 404


# ============================================================================
# VULNERABILITY 4: Missing Authorization (Admin Endpoint)
# ============================================================================
@app.route('/api/admin/users', methods=['GET'])
def list_all_users():
    """
    Missing Authorization - no role check
    
    Vulnerable: Any authenticated user can access admin endpoint
    Exploit: Regular user calls /api/admin/users
    """
    # VULNERABLE: No check if current user is admin
    # Missing: if session.get('role') != 'admin': return 403
    
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect('/tmp/vulnerable_app.db')
    c = conn.cursor()
    c.execute("SELECT id, username, email, role, balance FROM users")
    users = c.fetchall()
    conn.close()
    
    return jsonify({
        'users': [
            {'id': u[0], 'username': u[1], 'email': u[2], 'role': u[3], 'balance': u[4]}
            for u in users
        ]
    })


# ============================================================================
# VULNERABILITY 5: Business Logic Flaw (Price Manipulation)
# ============================================================================
@app.route('/api/checkout', methods=['POST'])
def checkout():
    """
    Business Logic Flaw - trusts client-sent prices
    
    Vulnerable: Client controls prices in checkout
    Exploit: Send {"items": [{"id": 1, "price": 0.01, "quantity": 100}]}
             Pay $1 for $100,000 worth of laptops
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    items = request.json.get('items', [])
    
    # VULNERABLE: Calculates total from CLIENT-SENT prices
    # Should validate prices against database
    total = 0
    for item in items:
        total += item['price'] * item['quantity']  # Uses client price!
    
    user_id = session['user_id']
    
    # Store order (just for demo)
    conn = sqlite3.connect('/tmp/vulnerable_app.db')
    c = conn.cursor()
    c.execute("INSERT INTO orders (user_id, total, items) VALUES (?, ?, ?)",
              (user_id, total, str(items)))
    order_id = c.lastrowid
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'order_id': order_id,
        'total': total,
        'message': f'Order placed successfully. Total: ${total:.2f}'
    })


# ============================================================================
# Additional Endpoints (Safe)
# ============================================================================
@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'app': 'custom-vulnerable-app', 'version': '1.0'})


@app.route('/api/info', methods=['GET'])
def info():
    """Application info endpoint"""
    return jsonify({
        'name': 'custom-vulnerable-app',
        'language': 'python',
        'framework': 'flask',
        'endpoints': [
            {'path': '/api/login', 'methods': ['POST'], 'vulnerable': True, 'type': 'SQL Injection'},
            {'path': '/api/search', 'methods': ['GET'], 'vulnerable': True, 'type': 'XSS'},
            {'path': '/api/user/<id>/profile', 'methods': ['GET'], 'vulnerable': True, 'type': 'IDOR'},
            {'path': '/api/admin/users', 'methods': ['GET'], 'vulnerable': True, 'type': 'Missing Authorization'},
            {'path': '/api/checkout', 'methods': ['POST'], 'vulnerable': True, 'type': 'Business Logic'},
            {'path': '/health', 'methods': ['GET'], 'vulnerable': False},
            {'path': '/api/info', 'methods': ['GET'], 'vulnerable': False}
        ],
        'known_vulnerabilities': 5,
        'purpose': 'Testing CPG-based security analysis'
    })


@app.route('/', methods=['GET'])
def index():
    """Simple landing page"""
    return """
    <html>
    <head><title>Custom Vulnerable App</title></head>
    <body>
        <h1>Custom Vulnerable Application</h1>
        <p>This application is intentionally vulnerable for security testing.</p>
        
        <h2>Available Endpoints:</h2>
        <ul>
            <li><strong>POST /api/login</strong> - Login (SQL Injection)</li>
            <li><strong>GET /api/search?q=...</strong> - Search products (XSS)</li>
            <li><strong>GET /api/user/&lt;id&gt;/profile</strong> - Get user profile (IDOR)</li>
            <li><strong>GET /api/admin/users</strong> - List all users (Missing Auth)</li>
            <li><strong>POST /api/checkout</strong> - Checkout (Business Logic)</li>
            <li><strong>GET /health</strong> - Health check</li>
            <li><strong>GET /api/info</strong> - Application info</li>
        </ul>
        
        <h2>Test Credentials:</h2>
        <ul>
            <li>admin / admin123 (role: admin)</li>
            <li>alice / alice123 (role: user)</li>
            <li>bob / bob123 (role: user)</li>
        </ul>
        
        <h2>Known Vulnerabilities:</h2>
        <ol>
            <li><strong>SQL Injection</strong> - Login endpoint accepts ' OR '1'='1' --</li>
            <li><strong>XSS</strong> - Search reflects input without escaping</li>
            <li><strong>IDOR</strong> - Profile endpoint has no authorization check</li>
            <li><strong>Missing Authorization</strong> - Admin endpoint accessible to all</li>
            <li><strong>Business Logic</strong> - Checkout trusts client-sent prices</li>
        </ol>
    </body>
    </html>
    """


if __name__ == '__main__':
    # Run on all interfaces, port 8888
    app.run(host='0.0.0.0', port=8888, debug=True)
