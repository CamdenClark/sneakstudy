CREATE TABLE `openrouter` (
	`id` integer PRIMARY KEY NOT NULL,
	`access_token` text NOT NULL,
	`balance` integer DEFAULT -1
);
