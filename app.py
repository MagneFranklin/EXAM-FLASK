from flask import Flask, render_template, request, redirect, url_for,flash
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'ClaveSuperSecreta'

# Configurar Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Obtener conexion a la base de datos
def get_db_conection():
    conn = sqlite3.connect('tareas.db')
    conn.row_factory = sqlite3.Row
    return conn

# Inicializar base de datos
def Init_db():
    conn = get_db_conection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            completed BOOLEAN NOT NULL DEFAULT 0,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()


# Clase Usuario para Flask-Login
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password = password_hash

    @staticmethod
    def get_by_id(user_id):
        conn = get_db_conection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id)).fetchone()       
        conn.close()
        if user:
            return User(user['id'], user['username'], user['password_hash'])
        return None

    @staticmethod
    def get_by_username(username):
        conn = get_db_conection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user:
            return User(user['id'], user['username'], user['password_hash'])
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)

@app.route('/')
def index():
    conn = get_db_conection()
    # Obtener todas las tareas almacenadas (no importa si el usuario está logueado o no)
    tasks = conn.execute('SELECT * FROM tasks').fetchall()
    conn.close()
    return render_template('index.html', tasks=tasks)  # Pasa todas las tareas a la plantilla


@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hash_pass = generate_password_hash(password)
        
        conn = get_db_conection()
        try:
            conn.execute(
                'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                (username, hash_pass)
            )
            conn.commit()
            flash('Usuario registrado correctamente. Inicia sesión.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('El nombre de usuario ya existe.', 'danger')
        finally:
            conn.close()
    return render_template('register.html')


@app.route('/login', methods = ['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.get_by_username(username)
        if user and check_password_hash(user.password, password):       
            login_user(user)
            flash('Inicio de sesión exitoso', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Credenciales inválidos', 'danger')
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    conn = get_db_conection()
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        conn.execute(
            'INSERT INTO tasks (title, description, user_id) VALUES (?, ?, ?)',
            (title, description, current_user.id)
        )
        conn.commit()

    tasks = conn.execute(
        'SELECT * FROM tasks WHERE user_id = ?', (current_user.id,)
    ).fetchall()
    conn.close()
    
    return render_template('dashboard.html', tasks=tasks, username=current_user.username)


@app.route('/task/new', methods=['GET', 'POST'])
@login_required
def new_task():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        conn = get_db_conection()
        conn.execute(
            'INSERT INTO tasks (title, description, user_id) VALUES (?, ?, ?)',
            (title, description, current_user.id)
        )
        conn.commit()
        conn.close()
        flash('Tarea creada exitosamente ✅', 'success')
        return redirect(url_for('dashboard'))
    return render_template('task_form.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión', 'info')
    return redirect(url_for('login'))


@app.route('/complete/<int:task_id>')
@login_required
def complete_task(task_id):
    conn = get_db_conection()
    conn.execute(
        'UPDATE tasks SET completed = 1 WHERE id = ? AND user_id = ?',
        (task_id, current_user.id)
    )
    conn.commit()
    conn.close()
    flash('Tarea completada ✅', 'success')
    return redirect(url_for('dashboard'))


@app.route('/delete/<int:task_id>')
@login_required
def delete_task(task_id):
    conn = get_db_conection()
    conn.execute(
        'DELETE FROM tasks WHERE id = ? AND user_id = ?',
        (task_id, current_user.id)
    )
    conn.commit()
    conn.close()
    flash('Tarea eliminada 🗑️', 'warning')
    return redirect(url_for('dashboard'))

@app.route('/edit/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    conn = get_db_conection()
    task = conn.execute(
        'SELECT * FROM tasks WHERE id = ? AND user_id = ?',
        (task_id, current_user.id)
    ).fetchone()

    if not task:
        conn.close()
        flash('Tarea no encontrada o acceso denegado', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        conn.execute(
            'UPDATE tasks SET title = ?, description = ? WHERE id = ? AND user_id = ?',
            (title, description, task_id, current_user.id)
        )
        conn.commit()
        conn.close()
        flash('Tarea actualizada correctamente ✏️', 'success')
        return redirect(url_for('dashboard'))

    conn.close()
    return render_template('edit_form.html', task=task)


if __name__ == '__main__':
    Init_db()
    app.run(debug=True)