from flask import render_template, request, flash, redirect, url_for, session
from flask.views import MethodView
from werkzeug.security import generate_password_hash, check_password_hash
from app import app, db, bcrypt
from app.forms import RegistrationForm, LoginForm, TransferForm
from app.models import Users, Transfer, Books
from flask_migrate import Migrate

migrate = Migrate(app, db)


@app.route("/", methods=["GET", "POST"])
def home():
    return render_template("home.html")


@app.route("/user_menu",methods=["GET","POST"])
def user_menu():
    if request.method == "GET":
        return render_template("blogs/user_menu.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            user = Users.query.filter_by(email=form.email.data).first()
            if user and bcrypt.check_password_hash(user.password, form.password.data):
                session['username'] = user.username
                flash('You are now logged in!', 'success')
                return redirect(url_for('user_menu'))
            else:
                flash("Invalid email or password", "danger")
                return redirect(url_for('login'))
    return render_template('auth/login.html', form=form)




@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = Users(
                username=form.username.data,
                # phone=form.phone.data,
                full_name=form.full_name.data,
                email=form.email.data,
                # balance=form.balance.data,
                password=hashed_password
            )
            db.session.add(user)
            db.session.commit()
            flash('You are now registered!', 'success')
            return redirect(url_for('login'))
    return render_template('auth/register.html', form=form)


@app.route("/my_books",methods=['GET', 'POST'])
def my_books():
    if request.method == 'POST':
        return redirect(url_for('user_menu'))
    username=session['username'];
    user=Users.query.filter_by(username=username).first()
    return render_template('blogs/my_books.html', user=user)

@app.route("/logout")
def logout():
    session.pop('username')
    return redirect(url_for('home'))

@app.route("/ad_books",methods=['GET', 'POST'])
def add_books():
    user = Users.query.filter_by(username=session['username']).first()
    if request.method == 'GET':
        return render_template("blogs/add_book.html")
    elif request.method == 'POST':
        num = request.form.get('num')
        num = int(num)
        if num < 0:
            flash('Please enter a positive number', 'danger')
        elif num:
            user.balance += num
            db.session.commit()
            flash('Balance successfully added!', 'success')
        return redirect(url_for('user_menu'))

@app.route("/delete_book",methods=['GET', 'POST'])
def delete_book():
    user = Users.query.filter_by(username=session['username']).first()
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('home'))


