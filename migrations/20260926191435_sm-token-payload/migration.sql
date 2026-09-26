ALTER TABLE `sm_access_tokens` ADD `encrypted_payload` text;--> statement-breakpoint
ALTER TABLE `sm_access_tokens` ADD `key` text;
--> statement-breakpoint
DELETE FROM sm_access_tokens WHERE "key" IS NULL;
