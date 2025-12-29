SET sql_log_bin=1;
CREATE DATABASE IF NOT EXISTS demo_db;
USE demo_db;
CREATE TABLE IF NOT EXISTS widgets (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(64),
    descr TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS parts (
    id INT PRIMARY KEY,
    widget_id INT,
    code CHAR(8),
    qty INT,
    UNIQUE KEY uq_code (code)
) ENGINE=InnoDB;

INSERT INTO widgets (name, descr) VALUES ('alpha', 'first'), ('beta', 'second')
ON DUPLICATE KEY UPDATE descr = VALUES(descr);
INSERT INTO parts (id, widget_id, code, qty) VALUES
    (1, 1, 'AA-0001', 10),
    (2, 1, 'AA-0002', 5),
    (3, 2, 'BB-0001', 1)
ON DUPLICATE KEY UPDATE qty = VALUES(qty);

UPDATE widgets SET descr = CONCAT(descr, ' updated') WHERE name = 'alpha';
UPDATE parts SET qty = qty + 1 WHERE code = 'AA-0002';
DELETE FROM parts WHERE code = 'BB-0001';
ALTER TABLE widgets ADD COLUMN IF NOT EXISTS notes JSON;
UPDATE widgets SET notes = JSON_OBJECT('status','ok') WHERE name = 'beta';
TRUNCATE TABLE parts;
DROP INDEX IF EXISTS uq_code ON parts;
ALTER TABLE parts ADD UNIQUE KEY uq_code (code);

-- idempotent cleanup/rotation
FLUSH LOGS;
