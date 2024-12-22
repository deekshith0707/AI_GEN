from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import openai
import os
import requests

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisisasecretkey'
openai.api_key = "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"  # Replace with your OpenAI API key

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                flash('Login successful!', 'success')  # Success message after login
                return redirect(url_for('dashboard'))
            else:
                flash('Login Unsuccessful. Please check your password.', 'danger')
        else:
            flash('Username does not exist. Please register.', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if current_user.is_authenticated:
        return render_template('dashboard.html')
    else:
        return redirect(url_for('login'))

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')  # Message after logout
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/generate', methods=['GET', 'POST'])
def generate():
    if not current_user.is_authenticated:
        flash("You must be logged in to generate an image.", "danger")
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        prompt = request.form.get('prompt', '')
        if not prompt:
            flash('Please provide a prompt.', 'warning')
            return redirect(url_for('home'))

        try:
            response = openai.Image.create(
                prompt=prompt,
                n=1,
                size="256x256"
            )
            image_url = response['data'][0]['url']

            # Download the image to a local file
            response = requests.get(image_url)
            file_path = os.path.join('static', 'generated_image.png')
            with open(file_path, 'wb') as file:
                file.write(response.content)

            return render_template('result.html', image_url=image_url, prompt=prompt, file_path=file_path)
        except openai.error.OpenAIError as e:
            flash(f"Error generating image: {str(e)}", "danger")
            return redirect(url_for('home'))
    return redirect(url_for('home'))

@app.route('/download/<filename>')
def download(filename):
    file_path = os.path.join('static', filename)
    try:
        return send_file(file_path, as_attachment=True)
    except FileNotFoundError:
        flash("File not found.", "danger")
        return redirect(url_for('home'))

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

if __name__ == "__main__":
    app.run(debug=True)
