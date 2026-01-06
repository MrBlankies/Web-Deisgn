from flask import Flask, request, render_template, flash, session, redirect
import sqlite3 
import hashlib 
from functools import wraps




app = Flask(__name__)
app.config['SESSION_TYPE'] = 'filesystem'
app.secret_key = "akjdsbkjas&^absdjkajbdkasbdksajbdksadbkbj"




def roles_permitted(roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if 'uid' in session and session['role'] in roles:
                return f(*args, **kwargs)
            else:
                flash(f'ERROR: you need {roles} role to access this page')
                return redirect('/login')
        return wrapper
    return decorator

def get_db_conn():
    db = sqlite3.connect('crm.db')
    db.row_factory = sqlite3.Row
    return db 

def initialize_db():
    db = get_db_conn()
    cursor = db.cursor() 

    cursor.execute("PRAGMA foreign_keys=ON")

    cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        uid INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL, 
                        password TEXT NOT NULL,
                        role TEXT DEFAULT 'employee',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        is_active TEXT DEFAULT 'active'
                    )
                   """)
    
    cursor.execute("""
                    CREATE TABLE IF NOT EXISTS customers (
                        cid INTEGER PRIMARY KEY AUTOINCREMENT,
                        created_by_user_id INTEGER,
                        last_name TEXT NOT NULL,
                        first_name TEXT NOT NULL,
                        notes TEXT,
                        address TEXT NOT NULL, 
                        status TEXT NOT NULL DEFAULT 'active',
                        email TEXT NOT NULL,
                        phone TEXT NOT NULL,
                        updated_at TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_contact_date TIMESTAMP,
                        FOREIGN KEY (created_by_user_id) REFERENCES users (uid)
                    )
                   """)
    
    cursor.execute("""
                    CREATE TABLE IF NOT EXISTS interactions (
                        iid INTEGER PRIMARY KEY AUTOINCREMENT,
                        customer_id INTEGER,
                        user_id INTEGER,
                        type TEXT NOT NULL DEFAULT 'phone',
                        interaction_date TIMESTAMP,
                        subject TEXT, 
                        notes TEXT,
                        customer_response TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (customer_id) REFERENCES customers (cid),
                        FOREIGN KEY (user_id) REFERENCES users (uid)
                    )        
                   """)
    
    db.commit()
    db.close()

def hash_password(password):
    pw = password
    hashed = hashlib.sha512(pw.encode('utf-8')).hexdigest()
    return hashed

@app.route('/')
def home():
    return render_template('login_form.html')
    
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/login', methods=[ 'GET', 'POST' ])
def login():
    username = ''
    db = get_db_conn()
    cursor = db.cursor()
    if request.method == 'POST':
        form = request.form
        username = form['username']
        password = form['password']
        user = cursor.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user:
            hashed_password = hash_password(password)
            if user['password'] == hashed_password:
                session['uid'] = user['uid']
                session['username'] = user['username']
                session['role'] = user['role']
                if user['role'] == 'employee':
                    return redirect('/employee')
                elif user['role'] == 'manager':
                    return redirect('/manager')
                elif user['role'] == 'admin':
                    return redirect('/admin')
            else:
                flash('ERROR: wrong credentials')
                return render_template('login_form.html', username=username)
        else:
            flash('ERROR: username not found')
            return render_template('login_form.html', username=username)
    else: 
        return render_template('login_form.html', username=username)
    



# EMPLOYEE ROUTES
@app.route('/employee')
@roles_permitted(['employee'])
def employee():
    db = get_db_conn()
    cursor = db.cursor()
    user_id = session['uid']
    interactions = cursor.execute("""
                                    SELECT i.*, c.first_name, c.last_name
                                    FROM interactions i
                                    JOIN customers c ON i.customer_id = c.cid
                                    WHERE i.user_id=?
                                        AND i.interaction_date >= date('now','-7 day')
                                    ORDER BY i.interaction_date DESC
                                   """, (user_id,)).fetchall()
    return render_template('employee/employee_dashboard.html', interactions=interactions)

@app.route('/customers')
@roles_permitted(['employee'])
def my_customers():
    db = get_db_conn()
    cursor = db.cursor()
    user_id = session['uid']
    customers = cursor.execute("SELECT * FROM customers WHERE created_by_user_id=?", (user_id,)).fetchall()
    customers_with_interactions = []
    for customer in customers:
        interactions = cursor.execute("SELECT * FROM interactions WHERE customer_id=?", (customer['cid'],)).fetchall()
        customer_dict = dict(customer)
        customer_dict['interactions'] = interactions
        customers_with_interactions.append(customer_dict)
    
    return render_template('employee/customers.html', customers=customers_with_interactions)

@app.route('/add/customer', methods=[ 'GET', 'POST' ])
@roles_permitted(['employee'])
def add_customer():
    db= get_db_conn()
    cursor = db.cursor()
    if request.method == 'POST':
        last_name = request.form['last_name']
        first_name = request.form['first_name']
        notes = request.form['notes']
        address = request.form['address']
        email = request.form['email']
        phone = request.form['phone']
        user_id = session['uid']
        cursor.execute("""
                        INSERT INTO customers 
                        (created_by_user_id, last_name, first_name, notes, address, email, phone) 
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                       """, 
                       (user_id, last_name, first_name, notes, address, email, phone))
        db.commit()
        return redirect('/customers')
    else:
        return render_template('employee/add_customer.html')
    
@app.route('/add/interaction/<int:cid>', methods=['GET', 'POST'])
@roles_permitted(['employee'])
def add_interaction(cid):
    db = get_db_conn()
    cursor = db.cursor()
    if request.method == 'POST':
        interaction_type = request.form['type']
        interaction_date = request.form['interaction_date']
        subject = request.form['subject']
        notes = request.form['notes']
        customer_response = request.form['customer_response']
        user_id = session['uid']
        cursor.execute("""
                        INSERT INTO interactions 
                        (customer_id, user_id, type, interaction_date, subject, notes, customer_response) 
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                       """, 
                       (cid, user_id, interaction_type, interaction_date, subject, notes, customer_response))
        cursor.execute("""
                        UPDATE customers 
                        SET last_contact_date=? 
                        WHERE cid=?
                       """, 
                       (interaction_date, cid))
        db.commit()
        db.close()
        return redirect(f'/customer/{cid}')
    else:
        customer = cursor.execute("SELECT * FROM customers WHERE cid=?", (cid,)).fetchone()
        return render_template('employee/add_interaction.html', customer=customer, cid=cid)
    
@app.route('/edit/interaction/<int:iid>', methods=['GET', 'POST'])
@roles_permitted(['employee'])
def edit_interaction(iid):
    db = get_db_conn()
    cursor = db.cursor()
    interaction = cursor.execute("SELECT * FROM interactions WHERE iid=?", (iid,)).fetchone()
    if not interaction:
        db.close()
        flash('ERROR: Interaction not found')
        return redirect('/customers')
    cid = interaction['customer_id']
    if request.method == 'POST':
        interaction_type = request.form['type']
        interaction_date = request.form['interaction_date']
        subject = request.form['subject']
        notes = request.form['notes']
        customer_response = request.form.get('customer_response', '')
        cursor.execute("""
                        UPDATE interactions 
                        SET type=?, interaction_date=?, subject=?, notes=?, customer_response=? 
                        WHERE iid=?
                       """, 
                       (interaction_type, interaction_date, subject, notes, customer_response, iid))
        db.commit()
        db.close()
        return redirect(f'/customer/{cid}')
    else:
        customer = cursor.execute("SELECT * FROM customers WHERE cid=?", (cid,)).fetchone()
        db.close()
        return render_template('employee/edit_interaction.html', interaction=interaction, customer=customer, cid=cid)

@app.route('/customer/<int:cid>')
@roles_permitted(['employee'])
def customer_details(cid):
    db = get_db_conn()
    cursor = db.cursor()
    customer = cursor.execute("SELECT * FROM customers WHERE cid=?", (cid,)).fetchone()
    interactions = cursor.execute("SELECT * FROM interactions WHERE customer_id=?", (cid,)).fetchall()
    if request.args.get('partial') == '1':
        return render_template('employee/customer_details_partial.html', 
                               customer=customer, interactions=interactions)
    return render_template('employee/customer_details.html', 
                           customer=customer, interactions=interactions)

@app.route('/edit/customer/<int:cid>', methods=['GET', 'POST'])
@roles_permitted(['employee'])
def edit_customer(cid):
    db = get_db_conn()
    cursor = db.cursor()
    if request.method == 'POST':
        last_name = request.form['last_name']
        first_name = request.form['first_name']
        notes = request.form['notes']
        address = request.form['address']
        email = request.form['email']
        phone = request.form['phone']
        customer = cursor.execute("SELECT * FROM customers WHERE cid=?", (cid,)).fetchone()
        if customer:
            cursor.execute("""
                        UPDATE customers 
                        SET last_name=?, first_name=?, notes=?, address=?, email=?, phone=? 
                        WHERE cid=?
                       """, 
                       (last_name, first_name, notes, address, email, phone, cid))
            db.commit()
            return redirect('/customers')
        else:
            flash("ERROR: Unable to edit customer")
            return redirect('/customers')
    else:
        customer = cursor.execute("SELECT * FROM customers WHERE cid=?", (cid,)).fetchone()
        return render_template('employee/edit_customer.html', customer=customer)

@app.route('/employee/statistics/<int:uid>')
@roles_permitted(['employee', 'manager'])
def manager_employee_statistics(uid):
    if session['role'] == 'employee' and session['uid'] != uid:
        flash('ERROR: You can only view your own statistics')
        return redirect('/employee')
    db = get_db_conn()
    cursor = db.cursor()
    customers = cursor.execute("SELECT COUNT(*) FROM customers WHERE created_by_user_id=?", (uid,)).fetchone()[0]
    
    contacts_30 = cursor.execute(
        "SELECT COUNT(*) FROM interactions WHERE user_id=? AND interaction_date >= date('now','-30 day')",
        (uid,)
    ).fetchone()[0]

    contacts_7 = cursor.execute(
        "SELECT COUNT(*) FROM interactions WHERE user_id=? AND interaction_date >= date('now','-7 day')",
        (uid,)
    ).fetchone()[0]

    contacts_1 = cursor.execute(
        "SELECT COUNT(*) FROM interactions WHERE user_id=? AND interaction_date >= date('now','-1 day')",
        (uid,)
    ).fetchone()[0]
    db.close()
    return render_template('employee/employee_statistics.html', customers=customers, contacts_30=contacts_30, contacts_7=contacts_7, contacts_1=contacts_1)
    


    
# MANAGER ROUTES
@app.route('/manager')
@roles_permitted(['manager'])
def manager():
    db = get_db_conn()
    cursor = db.cursor()

    cursor.execute("""
        SELECT 
            u.uid,
            u.username,
            u.role,
            u.is_active,
            u.created_at,
            -- count customers
            COUNT(DISTINCT c.cid) AS customer_count,
            -- count interactions last 30 days (subquery)
            (
                SELECT COUNT(*)
                FROM interactions i
                WHERE i.user_id = u.uid
                  AND i.interaction_date >= date('now', '-30 day')
            ) AS contacts_30
        FROM users u
        LEFT JOIN customers c
            ON u.uid = c.created_by_user_id
        WHERE u.role = 'employee'
        GROUP BY u.uid
        ORDER BY customer_count DESC
    """)
    all_users = cursor.fetchall()
    db.close()
    return render_template(
        'manager/manager_dashboard.html',
        top_employees=all_users
    )

@app.route('/employees')
@roles_permitted(['manager'])  
def employees():
    db = get_db_conn()
    cursor = db.cursor()
    
    cursor.execute("""
        SELECT 
            u.uid, 
            u.username, 
            u.role, 
            u.is_active, 
            u.created_at,
            COUNT(c.cid) AS customer_count
        FROM users u
        LEFT JOIN customers c ON u.uid = c.created_by_user_id
        GROUP BY u.uid
        ORDER BY customer_count DESC
    """)
    all_users = cursor.fetchall()
    
    db.close()
    return render_template('manager/employees.html', users=all_users)




# ADMIN ROUTES
@app.route('/admin')
@roles_permitted(['admin'])
def admin():
    return render_template('admin/admin_dashboard.html')

@app.route('/users')
@roles_permitted(['admin'])  
def users():
    db = get_db_conn()
    cursor = db.cursor()
    all_users = cursor.execute("SELECT * FROM users").fetchall()
    return render_template('admin/users.html', users=all_users)

@app.route('/disabled/users')
@roles_permitted(['admin'])  
def disabled_users():   
    db = get_db_conn()
    cursor = db.cursor()
    all_users = cursor.execute("SELECT * FROM users WHERE is_active='disabled'").fetchall()
    return render_template('admin/disabled_users.html', users=all_users)

@app.route('/edit/user/<int:uid>', methods=[ 'GET', 'POST' ])
@roles_permitted(['admin'])
def edit_user(uid):
    username = ''
    db = get_db_conn()
    cursor = db.cursor()
    if request.method == 'POST':
        username = request.form.get('username', '')
        role = request.form.get('role', 'employee')
        status = request.form.get('status', 'active')
        user = cursor.execute("SELECT * FROM users WHERE uid=?", (uid,)).fetchone()
        if user:
            if username != user['username']:
                cursor.execute("UPDATE users SET username=?, role=?, is_active=? WHERE uid =?", 
                              (username, role, status, uid))
            else:
                cursor.execute("UPDATE users SET username=?, role=?, is_active=? WHERE uid =?", 
                              (username, role, status, uid))
            db.commit()
            return redirect('/users')
        else:
            flash("ERROR: Unable to edit user")
            return redirect('/users')
    else:
        db.row_factory = sqlite3.Row
        cursor = db.cursor()
        user = cursor.execute("SELECT * FROM users WHERE uid=?", (uid,)).fetchone()
        return render_template('admin/edit_user.html', user=user)
    
@app.route('/delete/user/<int:uid>')
@roles_permitted(['admin'])
def delete_user(uid):
    db = get_db_conn()
    cursor = db.cursor()
    cursor.execute("DELETE FROM users WHERE uid=?", (uid,))
    db.commit()
    return redirect('/users')

@app.route('/register', methods=[ 'GET', 'POST' ])
@roles_permitted(['admin'])
def register():
    username = ''
    db = get_db_conn()
    cursor = db.cursor()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password2 = request.form['password2']
        if password != password2:
            flash("ERROR: Passwords do not match")
            return render_template('admin/register_form.html', username=username)
        else:
            user = cursor.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if user:
                flash("ERROR: Username is taken")
                return render_template('admin/register_form.html', username=username)
            else: 
                hashed_password = hash_password(password)
                cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                               (username, hashed_password))
                db.commit()
                return redirect('/admin')
    else:
        return render_template('admin/register_form.html', username=username)


if __name__ == '__main__':
    initialize_db()
    app.run(debug=True)

 