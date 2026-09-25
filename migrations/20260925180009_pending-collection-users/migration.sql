CREATE TABLE `pending_collection_users` (
	`membership_id` text NOT NULL,
	`collection_id` text NOT NULL,
	`read_only` integer DEFAULT 0 NOT NULL,
	`hide_passwords` integer DEFAULT 0 NOT NULL,
	`manage` integer DEFAULT 0 NOT NULL,
	CONSTRAINT `pending_collection_users_pk` PRIMARY KEY(`membership_id`, `collection_id`),
	CONSTRAINT `fk_pending_collection_users_membership_id_organization_memberships_id_fk` FOREIGN KEY (`membership_id`) REFERENCES `organization_memberships`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_pending_collection_users_collection_id_collections_id_fk` FOREIGN KEY (`collection_id`) REFERENCES `collections`(`id`) ON DELETE CASCADE
);
