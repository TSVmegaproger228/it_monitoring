from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, validators, SubmitField
from wtforms.validators import DataRequired, EqualTo
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import os
from flask_wtf.csrf import CSRFProtect


class RoleForm(FlaskForm):
    role = SelectField(
        'Роль',
        choices=[('user', 'Обычный пользователь'), ('admin', 'Администратор')],
        validators=[DataRequired()],
        render_kw={'disabled': False}
    )
    submit = SubmitField('Сохранить')


app = Flask(__name__)
app.config['SECRET_KEY'] = 'ваш_супер_секретный_ключ'
csrf = CSRFProtect(app)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'your_database.db')
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
app.config['SQLALCHEMY_ECHO'] = True

# Модель пользователя
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def is_self(self):
        return self.id == current_user.id


class RegistrationForm(FlaskForm):
    login = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[
        DataRequired(),
        EqualTo('confirm_password', message='Пароли должны совпадать')
    ])
    confirm_password = PasswordField('Повторите пароль')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Форма входа
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired

class LoginForm(FlaskForm):
    login = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


# Маршруты
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(login=form.login.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        flash('Неверный логин или пароль')
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(login=form.login.data).first()
        if existing_user:
            flash('Этот логин уже занят')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(form.password.data)
        new_user = User(
            login=form.login.data,
            password=hashed_password,
            role='user'  # По умолчанию регистрируем как обычного пользователя
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Регистрация прошла успешно! Теперь можно войти')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/admin/manage_roles', methods=['GET', 'POST'])
@admin_required
def manage_roles():
    users = User.query.all()
    print(f"DEBUG: Users count - {len(users)}")  # Проверьте в консоли Flask
    form = RoleForm()

    if form.validate_on_submit():
        user = User.query.filter_by(login=form.username.data).first()

        if user:
            # Проверка на попытку изменить свою роль
            if user.id == current_user.id:
                flash('Вы не можете изменить свою собственную роль!', 'danger')
            else:
                # Проверка на последнего админа
                if user.role == 'admin' and form.role.data == 'user':
                    if User.query.filter_by(role='admin').count() <= 1:
                        flash('Нельзя удалить последнего администратора!', 'danger')
                        return redirect(url_for('manage_roles'))

                user.role = form.role.data
                db.session.commit()
                flash(f'Роль пользователя {user.login} успешно изменена!', 'success')
        else:
            flash('Пользователь не найден!', 'danger')

        return redirect(url_for('manage_roles'))

    users = User.query.order_by(User.role.desc(), User.login).all()
    return render_template('admin/manage_roles.html', users=users)


@app.route('/admin/user/<int:user_id>/role', methods=['GET', 'POST'])
@admin_required
def manage_user_role(user_id):
    user = User.query.get_or_404(user_id)
    print(f"DEBUG: Старая роль - {user.role}")  # Добавьте это
    form = RoleForm()
    user.role = request.form.get('role')
    print(f"DEBUG: Новая роль - {user.role}")  # И это

    try:
        db.session.commit()
        print("DEBUG: Изменения сохранены!")  # Проверка коммита
    except Exception as e:
        print(f"DEBUG: Ошибка - {str(e)}")  # Логирование ошибки
        db.session.rollback()

    if form.validate_on_submit():
        try:
            # Проверка на изменение своей роли
            if user.id == current_user.id:
                flash('Вы не можете изменить свою собственную роль!', 'danger')
                return redirect(url_for('manage_users'))

            # Проверка на последнего админа
            if form.role.data == 'user' and user.role == 'admin':
                admins = User.query.filter_by(role='admin').count()
                if admins == 1:
                    flash('Нельзя удалить последнего администратора!', 'danger')
                    return redirect(url_for('manage_user_role', user_id=user.id))

            # Сохранение изменений
            if form.validate_on_submit():
                user.role = form.role.data
                db.session.commit()
                flash(f'Роль пользователя {user.login} изменена на {form.role.data}', 'success')
                return redirect(url_for('manage_users'))

        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка: {str(e)}', 'danger')
            app.logger.error(f'Error changing role: {str(e)}')

    elif request.method == 'POST':
        flash('Исправьте ошибки в форме', 'danger')

    return render_template('admin/edit_role.html', form=form, user=user)


@app.route('/admin/users')
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('users.html', users=users)


#добавление админа через консоль
@app.cli.command("create-admin")
def create_admin():
    """Создание администратора"""
    with app.app_context():
        if not User.query.filter_by(login='admin').first():
            admin = User(
                login='admin',
                password=generate_password_hash('!project_admin'),
                role='admin'
            )
            db.session.add(admin)
            db.session.commit()
            print("Администратор создан!")
        else:
            print("Администратор уже существует")


@app.cli.command("delete-all-users")
def delete_all_users():
    """Удаление всех пользователей"""
    with app.app_context():
        confirm = input("УДАЛИТЬ ВСЕХ ПОЛЬЗОВАТЕЛЕЙ? (y/n): ").lower()
        if confirm == 'y':
            deleted = User.query.delete()
            db.session.commit()
            print(f"Удалено {deleted} пользователей!")
        else:
            print("Отмена операции")


@app.before_request
def check_admin_count():
    if request.path.startswith('/admin'):  # Проверяем путь вместо endpoint
        admins_count = User.query.filter_by(role='admin').count()
        if admins_count < 1:
            abort(403, description="В системе должен быть хотя бы один администратор")


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Добавьте этот блок для вывода маршрутов
        print("\nДоступные маршруты:")
        for rule in app.url_map.iter_rules():
            print(f"{rule.endpoint}: {rule}")

    app.run(debug=True)