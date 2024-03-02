from flask import Flask, flash, render_template,redirect,url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,login_manager,login_user,logout_user,login_required,current_user,LoginManager
# from flask_wtf import wtforms this is removed by new update now its FlaskForm
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,TextAreaField,FileField
from wtforms.validators import input_required,ValidationError,Length,Email
from flask_bcrypt import Bcrypt
from flask_wtf.file import FileField, FileAllowed
from werkzeug.utils import secure_filename  
import os
#from flask_migrate import Migrate


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'secretkey'

db = SQLAlchemy(app)
bcrypt=Bcrypt(app)

login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view="Login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False,unique=True)
    email = db.Column(db.String(540), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    bio = db.Column(db.Text, nullable=True)
    profile_picture = db.Column(db.String(255), nullable=True)

class RegisterForm(FlaskForm):
    username = StringField(validators=[input_required(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    email = StringField(validators=[input_required(), Email(), Length(min=7, max=50)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[input_required(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("The username already exists, please choose a different one")

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError("The email already exists, please choose a different one")

class LoginForm(FlaskForm):
    usermail = StringField(validators=[input_required(), Length(min=4, max=20)], render_kw={"placeholder": "username or email"})
    password = PasswordField(validators=[input_required(), Length(min=4, max=20)], render_kw={"placeholder": "password"})
    submit = SubmitField("Login")

    def validate_usermail(self, usermail):
        user = User.query.filter((User.username == usermail.data) | (User.email == usermail.data)).first()

        if not user or not bcrypt.check_password_hash(user.password, self.password.data):
            raise ValidationError("Invalid username, email, or password")

#profile form
        
UPLOAD_FOLDER = r'C:\website\flask_sm\static\images'  
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
        
class ProfileSetupForm(FlaskForm):
    bio = TextAreaField('Bio', render_kw={"placeholder": "Tell us about yourself"})
    profile_picture = FileField('Profile Picture', validators=[FileAllowed(ALLOWED_EXTENSIONS, 'Only images allowed')])
    submit = SubmitField('Save Changes')



app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return render_template('home.html')


#user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter((User.username == form.usermail.data) | (User.email == form.usermail.data)).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))

    return render_template('login.html', form=form)


#dashboard after user succesfully logged in
@app.route('/dashboard',methods=['GET','POST'])
@login_required
def dashboard():
    form=ProfileSetupForm()
    if form.validate_on_submit:
        current_user.bio=form.bio.data

    if form.profile_picture.data:
            # Handle profile picture upload
            profile_picture = form.profile_picture.data
            filename = secure_filename(profile_picture.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            profile_picture.save(file_path)
            print("File Path:", file_path)
            # Update the profile_picture field with the file path
            current_user.profile_picture = file_path
            db.session.commit()
            flash('Profile updated successfully', 'success')
    return render_template('/dashboard.html',form=form)

#default page
@app.route('/register', methods=['GET', 'POST'])
def register_user():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

    # Print form validation errors to diagnose the issue
    print(form.errors)

    return render_template('register.html', form=form)

@app.route('/logout',methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)

app.config['SQLALCHEMY_ECHO'] = True