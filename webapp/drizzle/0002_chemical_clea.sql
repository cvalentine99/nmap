CREATE TABLE `cve_cache` (
	`id` int AUTO_INCREMENT NOT NULL,
	`cveId` varchar(64) NOT NULL,
	`description` text,
	`cvssV3Score` float,
	`cvssV3Severity` varchar(16),
	`cvssV3Vector` varchar(256),
	`cvssV4Score` float,
	`cvssV4Severity` varchar(16),
	`cweIds` json,
	`affectedProducts` json,
	`references` json,
	`publishedDate` timestamp,
	`lastModifiedDate` timestamp,
	`isKev` boolean NOT NULL DEFAULT false,
	`source` varchar(32) NOT NULL DEFAULT 'nvd',
	`rawJson` json,
	`fetchedAt` timestamp NOT NULL DEFAULT (now()),
	`expiresAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `cve_cache_id` PRIMARY KEY(`id`),
	CONSTRAINT `cve_cache_cveId_unique` UNIQUE(`cveId`)
);
--> statement-breakpoint
CREATE TABLE `cve_service_map` (
	`id` int AUTO_INCREMENT NOT NULL,
	`serviceName` varchar(256) NOT NULL,
	`product` varchar(256),
	`version` varchar(128),
	`cpeName` varchar(512),
	`cveId` varchar(64) NOT NULL,
	`cvssScore` float,
	`severity` varchar(16),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `cve_service_map_id` PRIMARY KEY(`id`)
);
