import random
from flask import Flask, render_template, redirect, request, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Length
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user, current_user
import requests
from email.message import EmailMessage
import ssl
import smtplib
from werkzeug.security import generate_password_hash, check_password_hash


emailer = None
username = None
password = None
id = None

sender = None
reciever = None

code = ''
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///user.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["SECRET_KEY"] = 'topsecret'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False)
    username = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    def __repr__(self):
        return f'{self.id}'

db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class form(FlaskForm):
    email = StringField()
    username = StringField()
    password = PasswordField()
    coder = StringField()
class form2(FlaskForm):
    email2 = StringField(validators=[InputRequired()])
    username2 = StringField(validators=[InputRequired(), Length(min=5, max=15)])
    password2 = PasswordField(validators=[InputRequired(), Length(min=8, max=18)])
    coder = StringField()
@app.route('/register', methods=["GET", "POST"])
def register():
    global User
    global code
    global emailer
    global username
    global password
    global id
    global reciever
    user = form2()
    num = 0
    if current_user.is_authenticated:
        return redirect('/main')
    if request.method == "POST":
        if request.form['submit_button'] == 'Sign Up':
            users = []
            emails = []
            for i in db.session.query(User).all():
                users.append(i.email)
                emails.append(i.username)
                print(i.email)
            if user.email2.data in users:
                flash('This email is already in use', 'info')
            elif user.username2.data in emails:
                flash('This username is already taken', 'info')
            else:
                api_key = "21860d4d-09e4-41b4-adb9-25d63ef70c40"
                email_address = user.email2.data
                response = requests.get(
                    "https://isitarealemail.com/api/email/validate",
                    params={'email': email_address},
                    headers={'Authorization': "Bearer " + api_key})

                status = response.json()['status']
                if status == "valid":
                    emailer = user.email2.data
                    username = user.username2.data
                    password = user.password2.data
                    id = len(db.session.query(User).all())
                    num += 1
                    code = ''
                    for i in range(6):
                        code = code + str(random.randint(1, 9))
                    mail = 'achishonia1234@gmail.com'
                    passer = 'xwnlvcrxwjyivwip'

                    msg = f"""
                    Code: {code}
                    """

                    em = EmailMessage()
                    em['From'] = mail
                    em["To"] = user.email2.data
                    em['Subject'] = 'Verification Code'
                    em.set_content(msg)

                    context = ssl.create_default_context()
                    reciever = user.email2.data
                    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
                        smtp.login(mail, passer)
                        smtp.sendmail(mail, user.email2.data, em.as_string())

                    return render_template('index.html', user=user, num=num)
                elif status == "invalid":
                    flash('Invalid Email', 'info')
                    return redirect('/register')
                else:
                    flash('Unknown Email, recommended to use Gmail, Yahoo, etc.', 'info')
                    return redirect('/register')
        if request.form['submit_button'] == 'Verify Code':
            if user.coder.data == code:
                flash('Registered Successfully', 'info')
                new_user = User(id=id + 1, email=emailer,
                                username=username, password=generate_password_hash(password))
                db.session.add(new_user)
                db.session.commit()

                return redirect('/login')
            else:
                flash('Incorrect Code')
                print('hello')
                num = 1
                return render_template('index.html', user=user, num=num)
        if request.form['submit_button'] == 'Resend Code':
            code = ''
            for i in range(6):
                code = code + str(random.randint(1, 9))
            mail = 'achishonia1234@gmail.com'
            passer = 'xwnlvcrxwjyivwip'

            msg = f"""
            Code: {code}
            """

            em = EmailMessage()
            em['From'] = mail
            em["To"] = reciever
            em['Subject'] = 'Verification Code'
            em.set_content(msg)

            context = ssl.create_default_context()

            with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
                smtp.login(mail, passer)
                smtp.sendmail(mail, reciever, em.as_string())
            num = 1
            return render_template('index.html', user=user, num=num)
    return render_template('index.html', user=user, num=num)
@app.route('/login', methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect('/main')
    user = form()
    global User
    global num
    num = 0
    if request.method == "POST":
        if "submit_button2" in request.form:
            return redirect('/register')
        elif "submit_button1" in request.form:
            print('omg')
            books = db.session.query(User).all()
            for i in books:
                book = User.query.filter_by(id=str(i)).first()
                if book.email == user.email.data:
                    if check_password_hash(book.password, user.password.data):
                        login_user(User.query.filter_by(username=book.username).first())
                        num += 1
                        return redirect('/main')
            if num == 0:
                flash('Username or password is incorrect')
                num = 0
    return render_template('login.html', user=user)

@app.route('/restore_password')
def resore():
    if current_user.is_authenticated:
        return redirect('/main')
    else:
        return render_template('restore.html')

@app.route('/main', methods=["GET", "POST"])
@login_required
def main():
    print(current_user.username)
    if request.method == "POST":
        logout_user()
        return redirect('/login')
    return render_template('top_G_secret.html', word=current_user.username)

if __name__ == "__main__":
    app.run(debug=True)