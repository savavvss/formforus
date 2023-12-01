from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'secret_key'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

user_chat_association = db.Table('user_chat_association',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('chat_id', db.Integer, db.ForeignKey('chat.id'))
)

class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    messages = db.relationship('Message', backref='chat', lazy=True)

# Обновление модели User
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    chats = db.relationship('Chat', secondary='user_chat_association', backref='users', lazy=True)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    chat_id = db.Column(db.Integer, db.ForeignKey('chat.id'), nullable=False)
    user = db.relationship('User', backref='messages', lazy=True)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha512')

        new_user = User(username=username, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Регистрация прошла успешно!', 'success')
            return redirect(url_for('login'))
        except:
            db.session.rollback()
            flash('Ошибка регистрации. Пожалуйста, попробуйте другое имя пользователя.', 'danger')

    return render_template('register.html')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def main():
    chats = Chat.query.all()
    return render_template('index.html', logged_in=current_user.is_authenticated, chats=chats)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Вход выполнен успешно!', 'success')
            return redirect(url_for('main'))
        else:
            flash('Неверное имя пользователя или пароль. Попробуйте снова.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы успешно вышли из системы.', 'info')
    return redirect(url_for('main'))

@app.route('/chat/<int:chat_id>', methods=['GET', 'POST'])
@login_required
def chat(chat_id):
    chat = Chat.query.get_or_404(chat_id)

    if request.method == 'POST':
        message_content = request.form['message']

        new_message = Message(content=message_content, user_id=current_user.id, chat_id=chat.id)

        try:
            db.session.add(new_message)
            db.session.commit()
            flash('Сообщение отправлено успешно!', 'success')
        except:
            db.session.rollback()
            flash('Ошибка отправки сообщения.', 'danger')

    return render_template('chat.html', chat=chat)

@app.route('/create_chat', methods=['POST'])
@login_required
def create_chat():
    chat_name = request.form['chat_name']
    new_chat = Chat(name=chat_name, user_id=current_user.id)

    try:
        db.session.add(new_chat)
        db.session.commit()
        flash('Чат создан успешно!', 'success')
    except:
        db.session.rollback()
        flash('Ошибка создания чата.', 'danger')

    return redirect(url_for('main'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
