CREATE TABLE `sm_project_groups` (
	`project_id` text NOT NULL,
	`group_id` text NOT NULL,
	`write_access` integer DEFAULT 0 NOT NULL,
	CONSTRAINT `sm_project_groups_pk` PRIMARY KEY(`project_id`, `group_id`),
	CONSTRAINT `fk_sm_project_groups_project_id_sm_projects_id_fk` FOREIGN KEY (`project_id`) REFERENCES `sm_projects`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_sm_project_groups_group_id_org_groups_id_fk` FOREIGN KEY (`group_id`) REFERENCES `org_groups`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `sm_project_members` (
	`project_id` text NOT NULL,
	`membership_id` text NOT NULL,
	`write_access` integer DEFAULT 0 NOT NULL,
	CONSTRAINT `sm_project_members_pk` PRIMARY KEY(`project_id`, `membership_id`),
	CONSTRAINT `fk_sm_project_members_project_id_sm_projects_id_fk` FOREIGN KEY (`project_id`) REFERENCES `sm_projects`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_sm_project_members_membership_id_organization_memberships_id_fk` FOREIGN KEY (`membership_id`) REFERENCES `organization_memberships`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `sm_secret_groups` (
	`secret_id` text NOT NULL,
	`group_id` text NOT NULL,
	`write_access` integer DEFAULT 0 NOT NULL,
	CONSTRAINT `sm_secret_groups_pk` PRIMARY KEY(`secret_id`, `group_id`),
	CONSTRAINT `fk_sm_secret_groups_secret_id_sm_secrets_id_fk` FOREIGN KEY (`secret_id`) REFERENCES `sm_secrets`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_sm_secret_groups_group_id_org_groups_id_fk` FOREIGN KEY (`group_id`) REFERENCES `org_groups`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `sm_secret_members` (
	`secret_id` text NOT NULL,
	`membership_id` text NOT NULL,
	`write_access` integer DEFAULT 0 NOT NULL,
	CONSTRAINT `sm_secret_members_pk` PRIMARY KEY(`secret_id`, `membership_id`),
	CONSTRAINT `fk_sm_secret_members_secret_id_sm_secrets_id_fk` FOREIGN KEY (`secret_id`) REFERENCES `sm_secrets`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_sm_secret_members_membership_id_organization_memberships_id_fk` FOREIGN KEY (`membership_id`) REFERENCES `organization_memberships`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `sm_secret_service_accounts` (
	`secret_id` text NOT NULL,
	`service_account_id` text NOT NULL,
	`write_access` integer DEFAULT 0 NOT NULL,
	CONSTRAINT `sm_secret_service_accounts_pk` PRIMARY KEY(`secret_id`, `service_account_id`),
	CONSTRAINT `fk_sm_secret_service_accounts_secret_id_sm_secrets_id_fk` FOREIGN KEY (`secret_id`) REFERENCES `sm_secrets`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_sm_secret_service_accounts_service_account_id_sm_service_accounts_id_fk` FOREIGN KEY (`service_account_id`) REFERENCES `sm_service_accounts`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `sm_service_account_groups` (
	`service_account_id` text NOT NULL,
	`group_id` text NOT NULL,
	CONSTRAINT `sm_service_account_groups_pk` PRIMARY KEY(`service_account_id`, `group_id`),
	CONSTRAINT `fk_sm_service_account_groups_service_account_id_sm_service_accounts_id_fk` FOREIGN KEY (`service_account_id`) REFERENCES `sm_service_accounts`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_sm_service_account_groups_group_id_org_groups_id_fk` FOREIGN KEY (`group_id`) REFERENCES `org_groups`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `sm_service_account_members` (
	`service_account_id` text NOT NULL,
	`membership_id` text NOT NULL,
	CONSTRAINT `sm_service_account_members_pk` PRIMARY KEY(`service_account_id`, `membership_id`),
	CONSTRAINT `fk_sm_service_account_members_service_account_id_sm_service_accounts_id_fk` FOREIGN KEY (`service_account_id`) REFERENCES `sm_service_accounts`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_sm_service_account_members_membership_id_organization_memberships_id_fk` FOREIGN KEY (`membership_id`) REFERENCES `organization_memberships`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE INDEX `idx_sm_project_groups_group` ON `sm_project_groups` (`group_id`);--> statement-breakpoint
CREATE INDEX `idx_sm_project_members_membership` ON `sm_project_members` (`membership_id`);--> statement-breakpoint
CREATE INDEX `idx_sm_secret_groups_group` ON `sm_secret_groups` (`group_id`);--> statement-breakpoint
CREATE INDEX `idx_sm_secret_members_membership` ON `sm_secret_members` (`membership_id`);--> statement-breakpoint
CREATE INDEX `idx_sm_secret_projects_project` ON `sm_secret_projects` (`project_id`);--> statement-breakpoint
CREATE INDEX `idx_sm_secret_service_accounts_service_account` ON `sm_secret_service_accounts` (`service_account_id`);--> statement-breakpoint
CREATE INDEX `idx_sm_service_account_groups_group` ON `sm_service_account_groups` (`group_id`);--> statement-breakpoint
CREATE INDEX `idx_sm_service_account_members_membership` ON `sm_service_account_members` (`membership_id`);--> statement-breakpoint
CREATE INDEX `idx_sm_sa_projects_project` ON `sm_service_account_projects` (`project_id`);--> statement-breakpoint
CREATE INDEX `idx_sm_service_accounts_org` ON `sm_service_accounts` (`org_id`);