from flask import Flask, render_template,  url_for, redirect, abort, session, flash
from flask_sqlalchemy import SQLAlchemy
from keras.preprocessing.image import load_img, img_to_array
from keras.models import load_model
from keras.applications.resnet50 import preprocess_input
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask import request

import os

app = Flask(__name__)
model_path = 'mango.h5'
model = load_model(model_path)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'Onchwari'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/mango'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mango.db'
db = SQLAlchemy(app)
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


class Test(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))


class Mango(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    farmnumber = db.Column(db.String(255))
    stage = db.Column(db.String(255))
    fieldofficer = db.Column(db.String(255))
    description = db.Column(db.String(255))

@app.route('/delete/<int:trigger_id>', methods=['POST', 'DELETE'])
@login_required
def delete_trigger(trigger_id):
    if current_user.username == 'admin':
        trigger = Mango.query.get_or_404(trigger_id)
        db.session.delete(trigger)
        db.session.commit()
        flash('Trigger deleted successfully', 'success')
    else:
        flash('You do not have permission to delete', 'danger')
    return redirect(url_for('triggers'))

def custom_decode_predictions(predictions, labels, top=3):
    decoded_predictions = []
    
    for prediction in predictions:
        top_indices = prediction.argsort()[-top:][::-1]
        top_predictions = [(labels[i], prediction[i]) for i in top_indices]
        decoded_predictions.append(top_predictions)
    
    return decoded_predictions


@app.route('/', methods=['GET'])


 

@app.route('/index', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            if user.username == 'admin':
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('home'))  

    return render_template('login.html', form=form)

@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    if current_user.username == 'admin':
        return redirect(url_for('admin'))
    else:
        return render_template('home.html')
    
@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/welcome')
def welcome():
    return render_template('welcome.html')

@app.route('/triggers')
@login_required
def triggers():
    triggers = Mango.query.all()

    return render_template('triggers.html', triggers=triggers)

@app.route('/aboutus')
@login_required
def aboutus():
    return render_template('aboutus.html')


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    return redirect(url_for('welcome'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/index', methods=['POST'])
@login_required
def predict():
    imagefile = request.files['imagefile']
    image_path = "./images/" + imagefile.filename
    imagefile.save(image_path)

    image = load_img(image_path, target_size=(256, 256))
    image = img_to_array(image)
    image = image.reshape((1, image.shape[0], image.shape[1], image.shape[2]))
    image = preprocess_input(image)

    predictions = model.predict(image)

    labels = ['Healthy','Powdery Mildew','Sooty Mould','Anthracnose','Bacterial Canker','Cutting Weevil','Die Back','Gall Midge']
    decoded_predictions = custom_decode_predictions(predictions, labels)

    top_prediction = decoded_predictions[0][0]
    classification = f"{top_prediction[0]} ({top_prediction[1]*100:.2f}%)"

    return render_template('predict.html', prediction=classification)
@app.route('/mango', methods=['POST'])
@login_required
def submit():
    if request.method == 'POST':
        name = request.form['name']
        farmnumber = int(request.form['farmnumber'])
        stage = request.form['stage']
        fieldofficer = int(request.form['fieldofficer'])
        description = request.form['description']

        mango_entry = Mango(
            name=name,
            farmnumber=farmnumber,
            stage=stage,
            fieldofficer=fieldofficer,
            description=description
        )
        db.session.add(mango_entry)
        db.session.commit()

        return redirect(url_for('triggers'))


@app.route('/admin')
@login_required
def admin():
    users = User.query.all()
    return render_template('admin.html', users=users)


@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Choose a different one.')
            return redirect(url_for('add_user'))
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        flash('User added successfully.')
        return redirect(url_for('all_users'))

    return render_template('add_user.html')

@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    user_to_delete = User.query.get(user_id)
    if user_to_delete:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash('User deleted successfully.')
    else:
        flash('User not found.')

    return redirect(url_for('all_users'))


if __name__ == '__main__':
    app.run(port=3000, debug=True)
