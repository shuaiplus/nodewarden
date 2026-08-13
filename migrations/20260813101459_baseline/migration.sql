CREATE TABLE `attachments` (
	`id` text PRIMARY KEY,
	`cipher_id` text NOT NULL,
	`file_name` text NOT NULL,
	`size` integer NOT NULL,
	`size_name` text NOT NULL,
	`key` text,
	CONSTRAINT `fk_attachments_cipher_id_ciphers_id_fk` FOREIGN KEY (`cipher_id`) REFERENCES `ciphers`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `audit_logs` (
	`id` text PRIMARY KEY,
	`actor_user_id` text,
	`action` text NOT NULL,
	`category` text DEFAULT 'system' NOT NULL,
	`level` text DEFAULT 'info' NOT NULL,
	`target_type` text,
	`target_id` text,
	`metadata` text,
	`created_at` text NOT NULL,
	CONSTRAINT `fk_audit_logs_actor_user_id_users_id_fk` FOREIGN KEY (`actor_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL
);
--> statement-breakpoint
CREATE TABLE `auth_requests` (
	`id` text PRIMARY KEY,
	`user_id` text NOT NULL,
	`organization_id` text,
	`type` integer NOT NULL,
	`request_device_identifier` text NOT NULL,
	`request_device_type` integer NOT NULL,
	`request_ip_address` text,
	`request_country_name` text,
	`response_device_identifier` text,
	`access_code` text NOT NULL,
	`public_key` text NOT NULL,
	`key` text,
	`master_password_hash` text,
	`approved` integer,
	`creation_date` text NOT NULL,
	`response_date` text,
	`authentication_date` text,
	CONSTRAINT `fk_auth_requests_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `cipher_collections` (
	`cipher_id` text NOT NULL,
	`collection_id` text NOT NULL,
	CONSTRAINT `cipher_collections_pk` PRIMARY KEY(`cipher_id`, `collection_id`),
	CONSTRAINT `fk_cipher_collections_cipher_id_ciphers_id_fk` FOREIGN KEY (`cipher_id`) REFERENCES `ciphers`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_cipher_collections_collection_id_collections_id_fk` FOREIGN KEY (`collection_id`) REFERENCES `collections`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `ciphers` (
	`id` text PRIMARY KEY,
	`user_id` text NOT NULL,
	`type` integer NOT NULL,
	`folder_id` text,
	`name` text,
	`notes` text,
	`favorite` integer DEFAULT 0 NOT NULL,
	`data` text NOT NULL,
	`reprompt` integer,
	`key` text,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	`archived_at` text,
	`deleted_at` text,
	`organization_id` text,
	CONSTRAINT `fk_ciphers_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `collection_groups` (
	`collection_id` text NOT NULL,
	`group_id` text NOT NULL,
	`read_only` integer DEFAULT 0 NOT NULL,
	`hide_passwords` integer DEFAULT 0 NOT NULL,
	`manage` integer DEFAULT 0 NOT NULL,
	CONSTRAINT `collection_groups_pk` PRIMARY KEY(`collection_id`, `group_id`),
	CONSTRAINT `fk_collection_groups_collection_id_collections_id_fk` FOREIGN KEY (`collection_id`) REFERENCES `collections`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_collection_groups_group_id_org_groups_id_fk` FOREIGN KEY (`group_id`) REFERENCES `org_groups`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `collection_users` (
	`user_id` text NOT NULL,
	`collection_id` text NOT NULL,
	`read_only` integer DEFAULT 0 NOT NULL,
	`hide_passwords` integer DEFAULT 0 NOT NULL,
	`manage` integer DEFAULT 0 NOT NULL,
	CONSTRAINT `collection_users_pk` PRIMARY KEY(`user_id`, `collection_id`),
	CONSTRAINT `fk_collection_users_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_collection_users_collection_id_collections_id_fk` FOREIGN KEY (`collection_id`) REFERENCES `collections`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `collections` (
	`id` text PRIMARY KEY,
	`org_id` text NOT NULL,
	`name` text NOT NULL,
	`external_id` text,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	CONSTRAINT `fk_collections_org_id_organizations_id_fk` FOREIGN KEY (`org_id`) REFERENCES `organizations`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `config` (
	`key` text PRIMARY KEY,
	`value` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `devices` (
	`user_id` text NOT NULL,
	`device_identifier` text NOT NULL,
	`name` text NOT NULL,
	`type` integer NOT NULL,
	`session_stamp` text,
	`encrypted_user_key` text,
	`encrypted_public_key` text,
	`encrypted_private_key` text,
	`push_uuid` text,
	`push_token` text,
	`banned` integer DEFAULT 0 NOT NULL,
	`banned_at` text,
	`device_note` text,
	`last_seen_at` text,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	CONSTRAINT `devices_pk` PRIMARY KEY(`user_id`, `device_identifier`),
	CONSTRAINT `fk_devices_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `domain_settings` (
	`user_id` text PRIMARY KEY,
	`equivalent_domains` text DEFAULT '[]' NOT NULL,
	`custom_equivalent_domains` text DEFAULT '[]' NOT NULL,
	`excluded_global_equivalent_domains` text DEFAULT '[]' NOT NULL,
	`updated_at` text NOT NULL,
	CONSTRAINT `fk_domain_settings_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `emergency_access` (
	`id` text PRIMARY KEY,
	`grantor_id` text NOT NULL,
	`grantee_id` text,
	`email` text,
	`key_encrypted` text,
	`type` integer NOT NULL,
	`status` integer NOT NULL,
	`wait_time_days` integer NOT NULL,
	`recovery_initiated_at` text,
	`last_notification_at` text,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	CONSTRAINT `fk_emergency_access_grantor_id_users_id_fk` FOREIGN KEY (`grantor_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_emergency_access_grantee_id_users_id_fk` FOREIGN KEY (`grantee_id`) REFERENCES `users`(`id`) ON DELETE SET NULL
);
--> statement-breakpoint
CREATE TABLE `folders` (
	`id` text PRIMARY KEY,
	`user_id` text NOT NULL,
	`name` text NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	CONSTRAINT `fk_folders_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `invites` (
	`code` text PRIMARY KEY,
	`created_by` text NOT NULL,
	`used_by` text,
	`expires_at` text NOT NULL,
	`status` text NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	CONSTRAINT `fk_invites_created_by_users_id_fk` FOREIGN KEY (`created_by`) REFERENCES `users`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_invites_used_by_users_id_fk` FOREIGN KEY (`used_by`) REFERENCES `users`(`id`) ON DELETE SET NULL
);
--> statement-breakpoint
CREATE TABLE `login_attempts_ip` (
	`ip` text PRIMARY KEY,
	`attempts` integer NOT NULL,
	`locked_until` integer,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `org_group_members` (
	`group_id` text NOT NULL,
	`membership_id` text NOT NULL,
	CONSTRAINT `org_group_members_pk` PRIMARY KEY(`group_id`, `membership_id`),
	CONSTRAINT `fk_org_group_members_group_id_org_groups_id_fk` FOREIGN KEY (`group_id`) REFERENCES `org_groups`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_org_group_members_membership_id_organization_memberships_id_fk` FOREIGN KEY (`membership_id`) REFERENCES `organization_memberships`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `org_groups` (
	`id` text PRIMARY KEY,
	`org_id` text NOT NULL,
	`name` text NOT NULL,
	`access_all` integer DEFAULT 0 NOT NULL,
	`external_id` text,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	CONSTRAINT `fk_org_groups_org_id_organizations_id_fk` FOREIGN KEY (`org_id`) REFERENCES `organizations`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `org_policies` (
	`id` text PRIMARY KEY,
	`org_id` text NOT NULL,
	`type` integer NOT NULL,
	`enabled` integer DEFAULT 0 NOT NULL,
	`data` text DEFAULT '{}' NOT NULL,
	`updated_at` text NOT NULL,
	CONSTRAINT `fk_org_policies_org_id_organizations_id_fk` FOREIGN KEY (`org_id`) REFERENCES `organizations`(`id`) ON DELETE CASCADE,
	CONSTRAINT `org_policies_org_id_type_unique` UNIQUE(`org_id`,`type`)
);
--> statement-breakpoint
CREATE TABLE `organization_api_keys` (
	`id` text PRIMARY KEY,
	`org_id` text NOT NULL,
	`type` integer DEFAULT 0 NOT NULL,
	`api_key` text NOT NULL,
	`revision_date` text NOT NULL,
	CONSTRAINT `fk_organization_api_keys_org_id_organizations_id_fk` FOREIGN KEY (`org_id`) REFERENCES `organizations`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `organization_memberships` (
	`id` text PRIMARY KEY,
	`user_id` text,
	`org_id` text NOT NULL,
	`email` text,
	`invited_by_email` text,
	`access_all` integer DEFAULT 0 NOT NULL,
	`key` text DEFAULT '' NOT NULL,
	`status` integer NOT NULL,
	`type` integer NOT NULL,
	`permissions` text,
	`reset_password_key` text,
	`external_id` text,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	CONSTRAINT `fk_organization_memberships_org_id_organizations_id_fk` FOREIGN KEY (`org_id`) REFERENCES `organizations`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_organization_memberships_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `organization_scim_tokens` (
	`org_id` text PRIMARY KEY,
	`token_hash` text NOT NULL,
	`created_at` text NOT NULL,
	CONSTRAINT `fk_organization_scim_tokens_org_id_organizations_id_fk` FOREIGN KEY (`org_id`) REFERENCES `organizations`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `organizations` (
	`id` text PRIMARY KEY,
	`name` text NOT NULL,
	`billing_email` text NOT NULL,
	`identifier` text,
	`private_key` text,
	`public_key` text,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `rate_limit_buckets` (
	`bucket_key` text PRIMARY KEY,
	`count` integer NOT NULL,
	`expires_at` integer NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `refresh_tokens` (
	`token` text PRIMARY KEY,
	`user_id` text NOT NULL,
	`expires_at` integer NOT NULL,
	`device_identifier` text,
	`device_session_stamp` text,
	`security_stamp` text,
	`created_at` integer,
	`last_used_at` integer,
	`absolute_expires_at` integer,
	`client_type` text,
	CONSTRAINT `fk_refresh_tokens_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `sends` (
	`id` text PRIMARY KEY,
	`user_id` text NOT NULL,
	`type` integer NOT NULL,
	`name` text NOT NULL,
	`notes` text,
	`data` text NOT NULL,
	`key` text NOT NULL,
	`password_hash` text,
	`password_salt` text,
	`password_iterations` integer,
	`auth_type` integer DEFAULT 2 NOT NULL,
	`emails` text,
	`max_access_count` integer,
	`access_count` integer DEFAULT 0 NOT NULL,
	`disabled` integer DEFAULT 0 NOT NULL,
	`hide_email` integer,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	`expiration_date` text,
	`deletion_date` text NOT NULL,
	CONSTRAINT `fk_sends_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `sm_access_tokens` (
	`id` text PRIMARY KEY,
	`service_account_id` text NOT NULL,
	`name` text NOT NULL,
	`client_secret_hash` text NOT NULL,
	`wrapped_org_key` text,
	`expire_at` text,
	`revoked_at` text,
	`created_at` text NOT NULL,
	CONSTRAINT `fk_sm_access_tokens_service_account_id_sm_service_accounts_id_fk` FOREIGN KEY (`service_account_id`) REFERENCES `sm_service_accounts`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `sm_projects` (
	`id` text PRIMARY KEY,
	`org_id` text NOT NULL,
	`name` text NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	CONSTRAINT `fk_sm_projects_org_id_organizations_id_fk` FOREIGN KEY (`org_id`) REFERENCES `organizations`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `sm_secret_projects` (
	`secret_id` text NOT NULL,
	`project_id` text NOT NULL,
	CONSTRAINT `sm_secret_projects_pk` PRIMARY KEY(`secret_id`, `project_id`),
	CONSTRAINT `fk_sm_secret_projects_secret_id_sm_secrets_id_fk` FOREIGN KEY (`secret_id`) REFERENCES `sm_secrets`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_sm_secret_projects_project_id_sm_projects_id_fk` FOREIGN KEY (`project_id`) REFERENCES `sm_projects`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `sm_secrets` (
	`id` text PRIMARY KEY,
	`org_id` text NOT NULL,
	`key` text NOT NULL,
	`value` text NOT NULL,
	`note` text,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	`deleted_at` text,
	CONSTRAINT `fk_sm_secrets_org_id_organizations_id_fk` FOREIGN KEY (`org_id`) REFERENCES `organizations`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `sm_service_account_projects` (
	`service_account_id` text NOT NULL,
	`project_id` text NOT NULL,
	`read_access` integer DEFAULT 1 NOT NULL,
	`write_access` integer DEFAULT 0 NOT NULL,
	CONSTRAINT `sm_service_account_projects_pk` PRIMARY KEY(`service_account_id`, `project_id`),
	CONSTRAINT `fk_sm_service_account_projects_service_account_id_sm_service_accounts_id_fk` FOREIGN KEY (`service_account_id`) REFERENCES `sm_service_accounts`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_sm_service_account_projects_project_id_sm_projects_id_fk` FOREIGN KEY (`project_id`) REFERENCES `sm_projects`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `sm_service_accounts` (
	`id` text PRIMARY KEY,
	`org_id` text NOT NULL,
	`name` text NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	CONSTRAINT `fk_sm_service_accounts_org_id_organizations_id_fk` FOREIGN KEY (`org_id`) REFERENCES `organizations`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `sso_auth` (
	`state` text PRIMARY KEY,
	`code_challenge` text,
	`redirect_uri` text NOT NULL,
	`client_id` text NOT NULL,
	`binding_hash` text,
	`identifier` text,
	`code_response` text,
	`code_response_error` text,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `sso_users` (
	`user_id` text PRIMARY KEY,
	`identifier` text NOT NULL UNIQUE,
	`created_at` text NOT NULL,
	CONSTRAINT `fk_sso_users_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `totp_login_replays` (
	`user_id` text NOT NULL,
	`time_counter` integer NOT NULL,
	`consumed_at` integer NOT NULL,
	CONSTRAINT `totp_login_replays_pk` PRIMARY KEY(`user_id`, `time_counter`),
	CONSTRAINT `fk_totp_login_replays_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `trusted_two_factor_device_tokens` (
	`token` text PRIMARY KEY,
	`user_id` text NOT NULL,
	`device_identifier` text NOT NULL,
	`expires_at` integer NOT NULL,
	CONSTRAINT `fk_trusted_two_factor_device_tokens_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `used_attachment_download_tokens` (
	`jti` text PRIMARY KEY,
	`expires_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `user_revisions` (
	`user_id` text PRIMARY KEY,
	`revision_date` text NOT NULL,
	CONSTRAINT `fk_user_revisions_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `users` (
	`id` text PRIMARY KEY,
	`email` text NOT NULL UNIQUE,
	`name` text,
	`master_password_hint` text,
	`master_password_hash` text NOT NULL,
	`key` text NOT NULL,
	`private_key` text,
	`public_key` text,
	`kdf_type` integer NOT NULL,
	`kdf_iterations` integer NOT NULL,
	`kdf_memory` integer,
	`kdf_parallelism` integer,
	`security_stamp` text NOT NULL,
	`role` text DEFAULT 'user' NOT NULL,
	`status` text DEFAULT 'active' NOT NULL,
	`verify_devices` integer DEFAULT 0 NOT NULL,
	`totp_secret` text,
	`totp_recovery_code` text,
	`yubikey_key1` text,
	`yubikey_key2` text,
	`yubikey_key3` text,
	`yubikey_key4` text,
	`yubikey_key5` text,
	`yubikey_nfc` integer DEFAULT 0 NOT NULL,
	`api_key` text,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `webauthn_challenges` (
	`challenge_hash` text PRIMARY KEY,
	`scope` text NOT NULL,
	`user_id` text,
	`expires_at` integer NOT NULL,
	`used_at` integer,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `webauthn_credentials` (
	`id` text PRIMARY KEY,
	`user_id` text NOT NULL,
	`purpose` text DEFAULT 'login' NOT NULL,
	`name` text NOT NULL,
	`public_key` text NOT NULL,
	`credential_id` text NOT NULL,
	`counter` integer DEFAULT 0 NOT NULL,
	`type` text,
	`aa_guid` text,
	`transports` text,
	`encrypted_user_key` text,
	`encrypted_public_key` text,
	`encrypted_private_key` text,
	`supports_prf` integer DEFAULT 0 NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	CONSTRAINT `fk_webauthn_credentials_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE INDEX `idx_attachments_cipher` ON `attachments` (`cipher_id`);--> statement-breakpoint
CREATE INDEX `idx_audit_logs_created_at` ON `audit_logs` (`created_at`);--> statement-breakpoint
CREATE INDEX `idx_audit_logs_actor_created` ON `audit_logs` (`actor_user_id`,`created_at`);--> statement-breakpoint
CREATE INDEX `idx_audit_logs_category_created` ON `audit_logs` (`category`,`created_at`);--> statement-breakpoint
CREATE INDEX `idx_audit_logs_level_created` ON `audit_logs` (`level`,`created_at`);--> statement-breakpoint
CREATE INDEX `idx_auth_requests_user_created` ON `auth_requests` (`user_id`,`creation_date`);--> statement-breakpoint
CREATE INDEX `idx_auth_requests_user_pending` ON `auth_requests` (`user_id`,`approved`,`response_date`,`authentication_date`,`creation_date`);--> statement-breakpoint
CREATE INDEX `idx_auth_requests_device_pending` ON `auth_requests` (`user_id`,`request_device_identifier`,`creation_date`);--> statement-breakpoint
CREATE INDEX `idx_cipher_collections_collection` ON `cipher_collections` (`collection_id`);--> statement-breakpoint
CREATE INDEX `idx_ciphers_user_updated` ON `ciphers` (`user_id`,`updated_at`);--> statement-breakpoint
CREATE INDEX `idx_ciphers_user_archived` ON `ciphers` (`user_id`,`archived_at`);--> statement-breakpoint
CREATE INDEX `idx_ciphers_user_deleted` ON `ciphers` (`user_id`,`deleted_at`);--> statement-breakpoint
CREATE INDEX `idx_ciphers_user_deleted_updated` ON `ciphers` (`user_id`,`deleted_at`,`updated_at`);--> statement-breakpoint
CREATE INDEX `idx_ciphers_user_folder` ON `ciphers` (`user_id`,`folder_id`);--> statement-breakpoint
CREATE INDEX `idx_ciphers_organization` ON `ciphers` (`organization_id`);--> statement-breakpoint
CREATE INDEX `idx_ciphers_user_personal` ON `ciphers` (`user_id`,`organization_id`,`updated_at`);--> statement-breakpoint
CREATE INDEX `idx_collections_org` ON `collections` (`org_id`);--> statement-breakpoint
CREATE INDEX `idx_devices_user_updated` ON `devices` (`user_id`,`updated_at`);--> statement-breakpoint
CREATE INDEX `idx_devices_user_last_seen` ON `devices` (`user_id`,`last_seen_at`);--> statement-breakpoint
CREATE INDEX `idx_devices_user_push` ON `devices` (`user_id`,`push_token`);--> statement-breakpoint
CREATE INDEX `idx_emergency_access_grantor` ON `emergency_access` (`grantor_id`,`status`);--> statement-breakpoint
CREATE INDEX `idx_emergency_access_grantee` ON `emergency_access` (`grantee_id`,`status`);--> statement-breakpoint
CREATE INDEX `idx_emergency_access_email` ON `emergency_access` (`email`);--> statement-breakpoint
CREATE INDEX `idx_folders_user_updated` ON `folders` (`user_id`,`updated_at`);--> statement-breakpoint
CREATE INDEX `idx_invites_status_expires` ON `invites` (`status`,`expires_at`);--> statement-breakpoint
CREATE INDEX `idx_invites_created_by` ON `invites` (`created_by`,`created_at`);--> statement-breakpoint
CREATE INDEX `idx_org_groups_org` ON `org_groups` (`org_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `idx_org_memberships_user_org` ON `organization_memberships` (`user_id`,`org_id`) WHERE "organization_memberships"."user_id" is not null;--> statement-breakpoint
CREATE INDEX `idx_org_memberships_org_status` ON `organization_memberships` (`org_id`,`status`);--> statement-breakpoint
CREATE INDEX `idx_org_memberships_external` ON `organization_memberships` (`org_id`,`external_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `idx_organizations_identifier` ON `organizations` (`identifier`) WHERE "organizations"."identifier" is not null;--> statement-breakpoint
CREATE INDEX `idx_rate_limit_buckets_expires` ON `rate_limit_buckets` (`expires_at`);--> statement-breakpoint
CREATE INDEX `idx_refresh_tokens_user` ON `refresh_tokens` (`user_id`);--> statement-breakpoint
CREATE INDEX `idx_sends_user_updated` ON `sends` (`user_id`,`updated_at`);--> statement-breakpoint
CREATE INDEX `idx_sends_user_deletion` ON `sends` (`user_id`,`deletion_date`);--> statement-breakpoint
CREATE INDEX `idx_sends_user_updated_id` ON `sends` (`user_id`,`updated_at`,`id`);--> statement-breakpoint
CREATE INDEX `idx_sm_projects_org` ON `sm_projects` (`org_id`);--> statement-breakpoint
CREATE INDEX `idx_sm_secrets_org_updated` ON `sm_secrets` (`org_id`,`updated_at`);--> statement-breakpoint
CREATE INDEX `idx_totp_login_replays_consumed_at` ON `totp_login_replays` (`consumed_at`);--> statement-breakpoint
CREATE INDEX `idx_trusted_two_factor_device_tokens_user_device` ON `trusted_two_factor_device_tokens` (`user_id`,`device_identifier`);--> statement-breakpoint
CREATE INDEX `idx_webauthn_challenges_expires` ON `webauthn_challenges` (`expires_at`);--> statement-breakpoint
CREATE INDEX `idx_webauthn_challenges_user_scope` ON `webauthn_challenges` (`user_id`,`scope`);--> statement-breakpoint
CREATE UNIQUE INDEX `idx_webauthn_credentials_id` ON `webauthn_credentials` (`id`);--> statement-breakpoint
CREATE UNIQUE INDEX `idx_webauthn_credentials_credential_id` ON `webauthn_credentials` (`credential_id`);--> statement-breakpoint
CREATE INDEX `idx_webauthn_credentials_user` ON `webauthn_credentials` (`user_id`);--> statement-breakpoint
CREATE INDEX `idx_webauthn_credentials_user_updated` ON `webauthn_credentials` (`user_id`,`updated_at`);