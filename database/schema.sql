BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "login_logs" (
	"log_id"	INTEGER,
	"username"	TEXT,
	"timestamp"	DATETIME DEFAULT CURRENT_TIMESTAMP,
	"success"	INTEGER,
	"ip_address"	TEXT,
	PRIMARY KEY("log_id" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "users" (
	"user_id"	INTEGER,
	"username"	TEXT NOT NULL UNIQUE,
	"password"	TEXT NOT NULL,
	PRIMARY KEY("user_id" AUTOINCREMENT)
);
COMMIT;
