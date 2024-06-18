from flask import Flask, flash, render_template, redirect, url_for, request,abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FileField
from wtforms.validators import InputRequired, ValidationError, Length, Email
from flask_bcrypt import Bcrypt
from flask_wtf.file import FileAllowed
from werkzeug.utils import secure_filename
import uuid
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'secretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#Class for user details and login
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(540), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    bio = db.Column(db.Text, nullable=True)
    profile_picture = db.Column(db.String(255), nullable=True)
    posts = db.relationship('Post', backref='author', lazy=True)   #for posts 


#class for user posts
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_filename = db.Column(db.String(255), nullable=False)  # Ensure this line exists
    caption = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

with app.app_context():
    db.create_all()


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    email = StringField(validators=[InputRequired(), Email(), Length(min=7, max=50)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
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
    usermail = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username or Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

    def validate_usermail(self, usermail):
        user = User.query.filter((User.username == usermail.data) | (User.email == usermail.data)).first()
        if not user or not bcrypt.check_password_hash(user.password, self.password.data):
            raise ValidationError("Invalid username, email, or password")


#form for deleting and adding posts

class PostForm(FlaskForm):
    photo = FileField('Photo', validators=[InputRequired(), FileAllowed(['jpg', 'jpeg', 'png'], 'Images only!')])
    caption = TextAreaField('Caption', validators=[Length(max=255)])
    submit = SubmitField('Post')

class DeletePostForm(FlaskForm):
    submit = SubmitField('Delete')




UPLOAD_FOLDER = r'static/images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

class ProfileSetupForm(FlaskForm):
    bio = TextAreaField('Bio', render_kw={"placeholder": "Tell us about yourself"})
    profile_picture = FileField('Profile Picture', validators=[FileAllowed(ALLOWED_EXTENSIONS, 'Only images allowed')])
    submit = SubmitField('Save Changes')

# with app.app_context():
#     db.create_all()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter((User.username == form.usermail.data) | (User.email == form.usermail.data)).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = ProfileSetupForm()
    if form.validate_on_submit():
        current_user.bio = form.bio.data
        if form.profile_picture.data:
            profile_picture = form.profile_picture.data
            filename = secure_filename(profile_picture.filename)
            pic_name = str(uuid.uuid1()) + "_" + filename
            profile_picture.save(os.path.join(app.config['UPLOAD_FOLDER'], pic_name))
            current_user.profile_picture = pic_name
        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('dashboard'))
    elif request.method == 'GET':
        form.bio.data = current_user.bio

    posts = Post.query.filter_by(user_id=current_user.id).all()
    delete_form = DeletePostForm()
    return render_template('dashboard.html', form=form, posts=posts, delete_form=delete_form)


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


#post photo route
@app.route('/post_photo', methods=['GET', 'POST'])
@login_required
def post_photo():
    form = PostForm()
    if form.validate_on_submit():
        photo = form.photo.data
        filename = secure_filename(photo.filename)
        pic_name = str(uuid.uuid1()) + "_" + filename
        photo.save(os.path.join(app.config['UPLOAD_FOLDER'], pic_name))
        
        new_post = Post(
            image_filename=pic_name,
            caption=form.caption.data,
            user_id=current_user.id
        )
        db.session.add(new_post)
        db.session.commit()
        flash('Photo posted successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('post.html', form=form)


@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id != current_user.id:
        abort(403)  # Forbidden
    db.session.delete(post)
    db.session.commit()
    flash('Post deleted successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

app.config['SQLALCHEMY_ECHO'] = True
