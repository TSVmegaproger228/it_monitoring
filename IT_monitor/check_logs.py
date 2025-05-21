from app import app, db, Device, MonitoringResult

with app.app_context():
    device = Device.query.first()
    if device:
        count = MonitoringResult.query.filter_by(device_id=device.id).count()
        print(f"Устройство: {device.name} (ID: {device.id})")
        print(f"Записей в журнале: {count}")

        # Вывод последних 5 записей
        logs = MonitoringResult.query.filter_by(device_id=device.id) \
            .order_by(MonitoringResult.timestamp.desc()) \
            .limit(5).all()
        for log in logs:
            print(f"{log.timestamp} | {log.status} | {log.details}")
    else:
        print("Устройства не найдены в базе данных")