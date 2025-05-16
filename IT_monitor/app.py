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
from flask_migrate import Migrate
import threading  # Добавьте этот импорт
import socket
import json
from datetime import timedelta
from sqlalchemy import func, case
import pandas as pd
import io
from flask import Response


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
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
app.config['SQLALCHEMY_ECHO'] = True

# Модель пользователя
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column('pass', db.String(100), nullable=False)  # Используем имя столбца из БД
    role = db.Column(db.String(20), nullable=False, default='user')

    def is_self(self):
        return self.id == current_user.id


class RegistrationForm(FlaskForm):
    login = StringField('Логин', validators=[DataRequired()])
    password_hash = PasswordField('Пароль', validators=[
        DataRequired(),
        EqualTo('confirm_password', message='Пароли должны совпадать')
    ])
    confirm_password = PasswordField('Повторите пароль')

# Модель устройства
class Device(db.Model):
    __tablename__ = 'devices'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(15), nullable=False)
    group = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Форма устройства
class DeviceForm(FlaskForm):
    name = StringField('Название', validators=[DataRequired()])
    ip_address = StringField('IP-адрес', validators=[DataRequired()])
    group = SelectField('Группа', choices=[
        ('servers', 'Серверы'),
        ('routers', 'Роутеры'),
        ('cameras', 'Камеры'),
        ('other', 'Другое')
    ], validators=[DataRequired()])
    description = StringField('Описание')
    submit = SubmitField('Сохранить')

# Модель результатов мониторинга
class MonitoringResult(db.Model):
    __tablename__ = 'monitoring_results'
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_online = db.Column(db.Boolean, nullable=False)
    ping_ms = db.Column(db.Float)
    port_status = db.Column(db.String(200))  # JSON с статусами портов

    device = db.relationship('Device', backref='monitoring_results')

class DeviceForm(FlaskForm):
    name = StringField('Название')
    submit = SubmitField('Сохранить')


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

# Модель оповещений
class Alert(db.Model):
    __tablename__ = 'alerts'
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    message = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_resolved = db.Column(db.Boolean, default=False)
    severity = db.Column(db.String(20))  # low, medium, high

    device = db.relationship('Device', backref='alerts')


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


# Функции мониторинга
def check_device(device):
    try:
        # Ping проверка
        response = ping(device.ip_address, count=1, timeout=2)
        is_online = response.success()
        ping_time = response.rtt_avg_ms if is_online else None

        # Проверка портов (пример для SSH и HTTP)
        port_status = {}
        if is_online:
            for port in [22, 80, 443]:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((device.ip_address, port))
                port_status[port] = 'open' if result == 0 else 'closed'
                sock.close()

        # Сохранение результата
        result = MonitoringResult(
            device_id=device.id,
            is_online=is_online,
            ping_ms=ping_time,
            port_status=json.dumps(port_status)
        )
        db.session.add(result)
        db.session.commit()

        # Создание оповещения при недоступности
        if not is_online:
            alert = Alert(
                device_id=device.id,
                message=f"Устройство {device.name} ({device.ip_address}) недоступно",
                severity='high'
            )
            db.session.add(alert)
            db.session.commit()

    except Exception as e:
        app.logger.error(f"Ошибка при проверке устройства {device.id}: {str(e)}")


# Планировщик проверок
def run_checks():
    with app.app_context():
        devices = Device.query.all()
        for device in devices:
            check_device(device)

        # Запускаем следующую проверку через 5 минут
        threading.Timer(300, run_checks).start()


# Маршруты
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(login=form.login.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
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

        hashed_password = generate_password_hash(form.password_hash.data)
        new_user = User(
            login=form.login.data,
            password_hash=generate_password_hash(form.password_hash.data),
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
    # Статистика устройств
    total_devices = Device.query.count()
    online_devices = db.session.query(Device).join(MonitoringResult).filter(
        MonitoringResult.is_online == True,
        MonitoringResult.timestamp == db.session.query(
            func.max(MonitoringResult.timestamp)
        ).filter(MonitoringResult.device_id == Device.id).correlate(Device)
    ).count()

    # Проблемные устройства
    problem_devices = db.session.query(Device).join(MonitoringResult).filter(
        MonitoringResult.is_online == False,
        MonitoringResult.timestamp == db.session.query(
            func.max(MonitoringResult.timestamp)
        ).filter(MonitoringResult.device_id == Device.id).correlate(Device)
    ).all()

    # История доступности за последние 24 часа
    time_24h_ago = datetime.utcnow() - timedelta(hours=24)
    history = db.session.query(
        func.strftime('%Y-%m-%d %H:00', MonitoringResult.timestamp).label('hour'),
        func.avg(case((MonitoringResult.is_online == True, 100), else_=0)).label('availability')
    ).filter(
        MonitoringResult.timestamp >= time_24h_ago
    ).group_by('hour').order_by('hour').all()

    return render_template('dashboard.html',
                           total_devices=total_devices,
                           online_devices=online_devices,
                           problem_devices=problem_devices,
                           availability_history=history)


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


# Маршруты для оповещений
@app.route('/alerts')
@login_required
def alert_list():
    alerts = Alert.query.filter_by(is_resolved=False).order_by(Alert.timestamp.desc()).all()
    return render_template('alerts/list.html', alerts=alerts)


@app.route('/alerts/<int:id>/resolve', methods=['POST'])
@login_required
def resolve_alert(id):
    alert = Alert.query.get_or_404(id)
    alert.is_resolved = True
    db.session.commit()
    flash('Оповещение помечено как решенное', 'success')
    return redirect(url_for('alert_list'))


# Генерация отчетов
@app.route('/reports/devices')
@login_required
def generate_device_report():
    devices = Device.query.all()
    data = []
    for device in devices:
        last_check = device.monitoring_results.order_by(MonitoringResult.timestamp.desc()).first()
        data.append({
            'Устройство': device.name,
            'IP': device.ip_address,
            'Группа': device.group,
            'Статус': 'Доступен' if last_check and last_check.is_online else 'Недоступен',
            'Последняя проверка': last_check.timestamp if last_check else 'Нет данных'
        })

    df = pd.DataFrame(data)
    output = io.StringIO()
    df.to_csv(output, index=False)
    output.seek(0)

    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=devices_report.csv"}
    )

#добавление админа через консоль
@app.cli.command("create-admin")
def create_admin():
    """Создание администратора"""
    with app.app_context():
        if not User.query.filter_by(login='admin').first():
            admin = User(
                login='admin',
                password_hash=generate_password_hash('!project_admin'),
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

@app.route('/devices')
@login_required
@app.route('/devices')
def device_list():
    devices = Device.query.all()
    form = FilterForm()  # Создайте форму для фильтрации
    return render_template('devices/list.html', devices=devices, form=form)

@app.route('/devices/add', methods=['GET', 'POST'])
@login_required
def add_device():
    form = DeviceForm()
    if form.validate_on_submit():
        device = Device(
            name=form.name.data,
            ip_address=form.ip_address.data,
            group=form.group.data,
            description=form.description.data
        )
        db.session.add(device)
        db.session.commit()
        flash('Устройство успешно добавлено', 'success')
        return redirect(url_for('device_list'))
    return render_template('devices/form.html', form=form, title='Добавить устройство')

@app.route('/devices/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_device(id):
    device = Device.query.get_or_404(id)
    form = DeviceForm(obj=device)
    if form.validate_on_submit():
        form.populate_obj(device)
        db.session.commit()
        flash('Устройство успешно обновлено', 'success')
        return redirect(url_for('device_list'))
    return render_template('devices/form.html', form=form, title='Редактировать устройство')

@app.route('/devices/<int:id>/delete', methods=['POST'])
@login_required
def delete_device(id):
    device = Device.query.get_or_404(id)
    db.session.delete(device)
    db.session.commit()
    flash('Устройство успешно удалено', 'success')
    return redirect(url_for('device_list'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Добавьте этот блок для вывода маршрутов
        print("\nДоступные маршруты:")
        # Запускаем проверки через 1 минуту после старта
        threading.Timer(60, run_checks).start()
        for rule in app.url_map.iter_rules():
            print(f"{rule.endpoint}: {rule}")

    app.run(debug=True)