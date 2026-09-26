UPDATE users SET verify_devices = 1 WHERE NOT EXISTS (SELECT 1 FROM config WHERE key = 'migration.verify-devices-on');
--> statement-breakpoint
INSERT OR IGNORE INTO config (key, value) VALUES ('migration.verify-devices-on', '1');
