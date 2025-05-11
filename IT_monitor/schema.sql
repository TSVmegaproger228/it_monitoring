-- Удалите все предыдущие таблицы, если они существуют
DROP TABLE IF EXISTS check_logs;
DROP TABLE IF EXISTS device_check_methods;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS check_methods;
DROP TABLE IF EXISTS device_type;
DROP TABLE IF EXISTS group_devices;
DROP TABLE IF EXISTS users;

-- Создание таблиц с явным указанием первичных ключей и ограничений
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login VARCHAR(50) NOT NULL UNIQUE,
    pass VARCHAR(100) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user'
);

CREATE TABLE group_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_name VARCHAR(100) NOT NULL UNIQUE
);

CREATE TABLE device_type (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type_name VARCHAR(50) NOT NULL UNIQUE
);

CREATE TABLE check_methods (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    method_name VARCHAR(100) NOT NULL UNIQUE,
    time_interval INTEGER NOT NULL
);

CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(50) NOT NULL,
    ip_address VARCHAR(50),
    domain_name VARCHAR(50),
    group_id INTEGER,
    type_id INTEGER,
    is_active BOOLEAN DEFAULT TRUE,
    last_status BOOLEAN,
    last_status_update TIMESTAMP,
    FOREIGN KEY (group_id) REFERENCES group_devices(id),
    FOREIGN KEY (type_id) REFERENCES device_type(id)
);

CREATE TABLE device_check_methods (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    method_id INTEGER NOT NULL,
    priority INTEGER DEFAULT 1,
    FOREIGN KEY (device_id) REFERENCES devices(id),
    FOREIGN KEY (method_id) REFERENCES check_methods(id)
);

CREATE TABLE check_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    method_id INTEGER NOT NULL,
    data TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id),
    FOREIGN KEY (method_id) REFERENCES check_methods(id)
);