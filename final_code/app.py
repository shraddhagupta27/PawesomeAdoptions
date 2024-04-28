from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from flask_admin.contrib.sqla import ModelView
from flask_admin import expose, Admin, AdminIndexView
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
from datetime import datetime
import csv 
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField
from wtforms.validators import InputRequired, DataRequired

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pet_adoption.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
csrf = CSRFProtect(app)

db = SQLAlchemy(app)

class Pet(db.Model):
    pet_id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.String, db.ForeignKey('organization.organization_id'))
    name = db.Column(db.String(127), nullable=False)
    breed = db.Column(db.String(64))
    age = db.Column(db.String(8), nullable=False)
    colors = db.Column(db.String(275))
    size = db.Column(db.String(20), nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    spayed_neutered = db.Column(db.Integer, nullable=False, default=0)
    house_trained = db.Column(db.Integer, nullable=False, default=0)
    shots_current = db.Column(db.Integer, nullable=False, default=0)
    pet_url = db.Column(db.String(127))
    description = db.Column(db.String(255))
    listed_on = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    pet_status = db.Column(db.String(10), nullable=False, default='adoptable')

class User(UserMixin, db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(127), nullable=False)
    email = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(150))
    phone = db.Column(db.String(14), unique=True)
    address = db.Column(db.String(255))
    is_admin = db.Column(db.Boolean, default=False)

    def get_id(self):
        return (self.user_id)

class Request(db.Model):
    request_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    pet_id = db.Column(db.Integer, db.ForeignKey('pet.pet_id'), nullable=False)
    requested_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    request_updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    request_status = db.Column(db.String(10), nullable=False, default='adoptable')

class Organization(db.Model):
    organization_id = db.Column(db.String, primary_key=True)
    email = db.Column(db.String(64))
    phone = db.Column(db.String(14))
    address = db.Column(db.String(255))


# def create_admin():
#     with app.app_context():
#         name = "Sarvesh"
#         email = "admin.sarvesh@gmail.com"
#         password = "admin123"
#         hashed_password = generate_password_hash(password)

#         admin_user = User(name=name, email=email, password=hashed_password, is_admin=True)
#         db.session.add(admin_user)
#         db.session.commit()
#         print("Admin user created!")

# create_admin()

class MyAdminIndexView(AdminIndexView):
    # base_template='admin/admin_base.html'

    @expose('/')
    def index(self):
        return self.render('admin/index.html')

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin


admin = Admin(app, name='Pawesome Admin', template_mode='bootstrap3', index_view=MyAdminIndexView(template='admin/index.html', url='/admin', endpoint='admin'))

class RestrictedModelView(ModelView):
    # base_template='admin/admin_base.html'

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))

class PetModelView(RestrictedModelView):
    column_list = ('pet_id', 'organization_id', 'name', 'breed', 'age', 'gender', 'size', 'spayed_neutered', 'house_trained', 'shots_current', 'pet_url', 'description', 'listed_on', 'pet_status')
    form_excluded_columns = ('pet_id', 'organization_id')

class UserModelView(RestrictedModelView):
    column_list = ('user_id', 'name', 'email', 'phone', 'address', 'is_admin')
    form_excluded_columns = ('user_id')

class OrganizationModelView(RestrictedModelView):
    column_list = ('organization_id', 'email', 'phone', 'address')
    form_excluded_columns = ('organization_id')

class RequestModelView(RestrictedModelView):
    column_list = ('request_id', 'user_id', 'pet_id', 'requested_at', 'request_updated_at', 'request_status')
    form_excluded_columns = ('request_id', 'user_id', 'pet_id')

    def on_model_change(self, form, model, is_created):
        """This method is called on model change to handle additional logic."""
        if model.request_status == 'accepted':
            pet = Pet.query.get(model.pet_id)
            pet.pet_status = 'adopted'
            db.session.add(pet)

            # Decline other requests
            other_requests = Request.query.filter(Request.pet_id == model.pet_id, Request.request_id != model.request_id).all()
            for req in other_requests:
                req.request_status = 'declined'
                db.session.add(req)

        db.session.commit()  # Ensure all changes are committed

    def on_model_delete(self, model):
        """This method is called before a model is deleted to handle cleanup if necessary."""
        pass



admin.add_view(PetModelView(Pet, db.session, name='Pets'))
admin.add_view(UserModelView(User, db.session, name='Users'))
admin.add_view(OrganizationModelView(Organization, db.session, name='Organizations'))
admin.add_view(RequestModelView(Request, db.session, name='Requests'))


@app.before_request
def restrict_admin_panel():
    if request.path.startswith('/admin/') and not (current_user.is_authenticated and current_user.is_admin):
        return redirect(url_for('login'))


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



def populate_pets_from_csv(filepath):
    df = pd.read_csv(filepath)
    for _, row in df.iterrows():

        listed_on = row['listed_on']
        if '+' in listed_on:
            listed_on = listed_on.split('+')[0].strip()
        listed_on = datetime.strptime(listed_on, '%Y-%m-%d %H:%M:%S')
      
        pet = Pet(
            pet_id=row['pet_id'],
            organization_id=row['organization_id'],
            name=row['name'],
            breed=row.get('breed', ''),
            age=row['age'],
            colors=row.get('colors', ''),
            size=row['size'],
            gender=row['gender'],
            spayed_neutered=row['spayed_neutered'],
            house_trained=row['house_trained'],
            shots_current=row['shots_current'],
            pet_url=row['pet_url'],
            description=row.get('description', ''),
            listed_on=listed_on,
            pet_status=row['pet_status']
        )
        db.session.add(pet)
    db.session.commit()

def populate_org_from_csv(csv_path):
    with app.app_context():
        with open(csv_path, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                try:
                    phone_cleaned = ''.join(filter(str.isdigit, row['phone'])) if row['phone'] else None
                    org = Organization(
                        organization_id=row['organization_id'],
                        email=row['email'],
                        phone=phone_cleaned,
                        address=row.get('address', '')
                    )
                    db.session.add(org)
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    print(f"Failed to add {row['organization_id']} due to {e}")


# with app.app_context():
#     db.drop_all()
#     db.create_all()

with app.app_context():
    db.create_all()
    if not Pet.query.first():
        populate_pets_from_csv('D:/Sarvesh/USA/IUB/SEM 2 Spring 2024/DSCI-D532 Applied Database Technologies/proj_adt/proj_adt/Pet.csv')
    if not Organization.query.first():
        populate_org_from_csv('D:/Sarvesh/USA/IUB/SEM 2 Spring 2024/DSCI-D532 Applied Database Technologies/proj_adt/proj_adt/Org.csv')
    # name = "Sarvesh"
    # email = "admin.sarvesh@gmail.com"
    # password = "admin123"
    # hashed_password = generate_password_hash(password)

    # admin_user = User(name=name, email=email, password=hashed_password, is_admin=True)
    # db.session.add(admin_user)
    # db.session.commit()
    # print("Admin user created!")



@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    query = Pet.query.filter(Pet.pet_status == 'adoptable')

    # Applying filters (if any)
    name = request.args.get('name')
    breed_filter = request.args.get('breed')
    gender = request.args.get('gender')
    age_filter = request.args.get('age')
    size_filter = request.args.get('size')

    if name:
        query = query.filter(Pet.name.ilike(f'%{name}%'))
    if breed_filter:
        query = query.filter(Pet.breed.ilike(f'%{breed_filter}%'))
    if gender:
        query = query.filter(Pet.gender == gender)
    if age_filter:
        query = query.filter(Pet.age == age_filter)
    if size_filter:
        query = query.filter(Pet.size == size_filter)

    pets = query.paginate(page=page, per_page=15, error_out=False)

    # Fetching unique values for filters
    # Fetching and processing unique values for the breed filter
    breed_data = db.session.query(Pet.breed).distinct().all()
    breeds = set()
    for (breed_string,) in breed_data:
        breed_list = breed_string.split(',')
        breeds.update(breed for breed in breed_list)
    breeds = sorted(breeds)

    # Handling breed filter
    breed_filter = request.args.get('breed')
    if breed_filter:
        query = query.filter(Pet.breed.ilike(f'%{breed_filter}%'))

    ages = db.session.query(Pet.age).distinct().all()
    sizes = db.session.query(Pet.size).distinct().all()

    # Flattening lists
    breeds = [b for b in breeds if b[0] is not None]
    ages = [a[0] for a in ages if a[0] is not None]
    sizes = [s[0] for s in sizes if s[0] is not None]

    # Sorting logic
    sort = request.args.get('sort', 'date_desc') 
    if sort == 'date_desc':
        query = query.order_by(Pet.listed_on.desc())
    elif sort == 'age':
        query = query.order_by(Pet.age)
    elif sort == 'size':
        query = query.order_by(Pet.size)

    return render_template('index.html', pets=pets, breeds=breeds, ages=ages, sizes=sizes, sort=sort)


class LoginForm(FlaskForm):
    email = StringField('Email', [InputRequired()])
    password = PasswordField('Password', [InputRequired()])

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            if user.is_admin:
                return redirect(url_for('admin.index'))
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html', form=form)


class UserDetailsForm(FlaskForm):
    phone = StringField('Phone', validators=[DataRequired()])
    address = TextAreaField('Address', validators=[DataRequired()])

@app.route('/user_details', methods=['GET', 'POST'])
@login_required
def user_details():
    form = UserDetailsForm()
    if form.validate_on_submit():
        return redirect(url_for('index'))
    user_requests = Request.query.filter_by(user_id=current_user.user_id).all()
    return render_template('user_details.html', form=form, user_requests=user_requests, csrf_token=generate_csrf())

@app.route('/update_user_details', methods=['POST'])
@login_required
def update_user_details():
    user = User.query.get(current_user.user_id)  
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('index'))

    user.phone = request.form['phone']
    user.address = request.form['address']
    db.session.commit()
    
    flash('Your details have been updated.', 'success')
    return redirect(url_for('index'))


@app.route('/about', methods=['GET'])
def about():
    return render_template('about.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        if not name or not email or not password:
            return "Please fill in all fields", 400

        hashed_password = generate_password_hash(password)
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return "An account with this email already exists."

        user = User(name=name, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html', csrf_token=generate_csrf())


@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('index'))



@app.route('/pet/<int:pet_id>')
def pet_detail(pet_id):
    pet = Pet.query.get_or_404(pet_id)
    return render_template('pet_detail.html', pet=pet)


@app.route('/request_adoption/<int:pet_id>', methods=['POST'])
@login_required
def request_adoption(pet_id):
    pet = Pet.query.get_or_404(pet_id)
    if pet.pet_status != 'adoptable':
        flash('Sorry, this pet has already been adopted.', 'error')
        return redirect(url_for('pet_detail', pet_id=pet_id))

    existing_request = Request.query.filter_by(user_id=current_user.user_id, pet_id=pet_id).first()
    if existing_request:
        flash('You have already shown interest in adopting this pet.', 'info')
        return redirect(url_for('pet_detail', pet_id=pet_id))

    adoption_request = Request(
        user_id=current_user.user_id,
        pet_id=pet_id,
        request_status='pending'
    )
    db.session.add(adoption_request)
    db.session.commit()
    flash('Your interest has been registered. You can check the Request Status in My Profile.', 'success')
    return redirect(url_for('pet_detail', pet_id=pet_id))

def request_status_listener(mapper, connection, target):
    """Listener that is triggered when a Request's status is changed."""
    if target.request_status == 'accepted':
        # Update the pet status to 'adopted'
        pet = db.session.query(Pet).get(target.pet_id)
        pet.pet_status = 'adopted'
        
        # Decline other requests for the same pet
        other_requests = db.session.query(Request)\
            .filter(Request.pet_id == target.pet_id)\
            .filter(Request.request_id != target.request_id)\
            .all()
        for req in other_requests:
            req.request_status = 'declined'

event.listen(Request, 'before_update', request_status_listener)



if __name__ == '__main__':
    app.run(debug=True)

