CREATE TABLE `audit_log` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int,
	`userName` varchar(256),
	`action` enum('scan_created','scan_started','scan_completed','scan_failed','scan_cancelled','scan_deleted','cidr_added','cidr_removed','cidr_toggled','settings_changed','user_login','user_logout','export_generated','cuda_enabled','cuda_disabled') NOT NULL,
	`details` text,
	`entityType` varchar(64),
	`entityId` int,
	`ipAddress` varchar(45),
	`metadata` json,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `audit_log_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `cidr_rules` (
	`id` int AUTO_INCREMENT NOT NULL,
	`cidr` varchar(64) NOT NULL,
	`label` varchar(256),
	`type` enum('allow','deny') NOT NULL DEFAULT 'allow',
	`enabled` boolean NOT NULL DEFAULT true,
	`createdBy` int,
	`notes` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `cidr_rules_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `cuda_devices` (
	`id` int AUTO_INCREMENT NOT NULL,
	`deviceIndex` int NOT NULL,
	`deviceName` varchar(256) NOT NULL,
	`computeCapability` varchar(16),
	`totalMemory` bigint,
	`freeMemory` bigint,
	`utilization` int,
	`temperature` int,
	`powerDraw` float,
	`available` boolean NOT NULL DEFAULT true,
	`driverVersion` varchar(32),
	`cudaVersion` varchar(32),
	`lastCheckedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `cuda_devices_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `hosts` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scanId` int NOT NULL,
	`ip` varchar(45) NOT NULL,
	`hostname` varchar(512),
	`state` enum('up','down','unknown') NOT NULL DEFAULT 'up',
	`osName` varchar(256),
	`osFamily` varchar(128),
	`osAccuracy` int,
	`macAddress` varchar(17),
	`macVendor` varchar(256),
	`hops` int,
	`latency` float,
	`openPortCount` int DEFAULT 0,
	`filteredPortCount` int DEFAULT 0,
	`closedPortCount` int DEFAULT 0,
	`latitude` float,
	`longitude` float,
	`country` varchar(128),
	`city` varchar(256),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `hosts_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `ports` (
	`id` int AUTO_INCREMENT NOT NULL,
	`hostId` int NOT NULL,
	`scanId` int NOT NULL,
	`portNumber` int NOT NULL,
	`protocol` enum('tcp','udp','sctp') NOT NULL DEFAULT 'tcp',
	`state` varchar(32) NOT NULL,
	`service` varchar(128),
	`product` varchar(256),
	`version` varchar(128),
	`extraInfo` text,
	`cpe` text,
	`riskLevel` enum('critical','high','medium','low','info'),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `ports_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `scan_templates` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(256) NOT NULL,
	`description` text,
	`flags` text,
	`category` varchar(128),
	`cudaRecommended` boolean NOT NULL DEFAULT false,
	`isSystem` boolean NOT NULL DEFAULT false,
	`createdBy` int,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `scan_templates_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `scans` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`target` varchar(1024) NOT NULL,
	`profile` varchar(128),
	`flags` text,
	`command` text,
	`status` enum('queued','running','completed','failed','cancelled') NOT NULL DEFAULT 'queued',
	`cudaEnabled` boolean NOT NULL DEFAULT false,
	`cudaDevice` varchar(256),
	`progress` int DEFAULT 0,
	`hostsUp` int DEFAULT 0,
	`hostsDown` int DEFAULT 0,
	`openPorts` int DEFAULT 0,
	`filteredPorts` int DEFAULT 0,
	`vulnCount` int DEFAULT 0,
	`durationMs` bigint,
	`rawXml` text,
	`nmapVersion` varchar(64),
	`errorMessage` text,
	`startedAt` timestamp,
	`completedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `scans_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `vulnerabilities` (
	`id` int AUTO_INCREMENT NOT NULL,
	`hostId` int NOT NULL,
	`portId` int,
	`scanId` int NOT NULL,
	`scriptId` varchar(256),
	`scriptName` varchar(256),
	`severity` enum('critical','high','medium','low','info') NOT NULL DEFAULT 'info',
	`cveId` varchar(64),
	`cvssScore` float,
	`title` varchar(512),
	`output` text,
	`remediation` text,
	`acknowledged` boolean NOT NULL DEFAULT false,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `vulnerabilities_id` PRIMARY KEY(`id`)
);
