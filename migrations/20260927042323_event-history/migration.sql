CREATE TABLE `events` (
	`id` text PRIMARY KEY,
	`organization_id` text,
	`type` integer NOT NULL,
	`date` text NOT NULL,
	`recorded_at` text NOT NULL,
	`acting_user_id` text,
	`user_id` text,
	`resource_type` text,
	`resource_id` text,
	`service_account_id` text,
	`granted_service_account_id` text,
	`device_type` integer,
	`ip_address` text,
	`system_user` integer,
	CONSTRAINT `fk_events_organization_id_organizations_id_fk` FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE INDEX `idx_events_recorded` ON `events` (`recorded_at`,`id`);--> statement-breakpoint
CREATE INDEX `idx_events_org_date` ON `events` (`organization_id`,`date`,`id`);--> statement-breakpoint
CREATE INDEX `idx_events_actor_date` ON `events` (`acting_user_id`,`date`,`id`);--> statement-breakpoint
CREATE INDEX `idx_events_resource_date` ON `events` (`organization_id`,`resource_type`,`resource_id`,`date`,`id`);