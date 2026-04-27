CREATE TABLE `alerts` (
	`id` int AUTO_INCREMENT NOT NULL,
	`healthCenterId` int NOT NULL,
	`patientRecordId` int,
	`alertType` enum('severe_case','critical_registration','high_satisfaction_drop','anomaly') NOT NULL,
	`severity` enum('info','warning','critical') NOT NULL,
	`title` varchar(255) NOT NULL,
	`description` text,
	`isRead` boolean NOT NULL DEFAULT false,
	`readBy` int,
	`readAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `alerts_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `analysis_results` (
	`id` int AUTO_INCREMENT NOT NULL,
	`healthCenterId` int NOT NULL,
	`analysisType` enum('descriptive','ai_insights','trend') NOT NULL,
	`totalPatients` int DEFAULT 0,
	`femalePercentage` decimal(5,2),
	`averageAge` decimal(5,2),
	`averageTemperature` decimal(4,1),
	`averageSatisfaction` decimal(3,2),
	`severeCount` int DEFAULT 0,
	`aiInsights` text,
	`aiModel` varchar(50) DEFAULT 'claude-3-sonnet',
	`generatedAt` timestamp NOT NULL DEFAULT (now()),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `analysis_results_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `audit_logs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`healthCenterId` int,
	`action` varchar(100) NOT NULL,
	`entityType` varchar(50) NOT NULL,
	`entityId` int,
	`changes` json,
	`ipAddress` varchar(45),
	`userAgent` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `audit_logs_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `export_history` (
	`id` int AUTO_INCREMENT NOT NULL,
	`healthCenterId` int NOT NULL,
	`exportedBy` int NOT NULL,
	`exportType` enum('csv','pdf') NOT NULL,
	`recordCount` int DEFAULT 0,
	`fileName` varchar(255),
	`fileUrl` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `export_history_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `health_centers` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`region` varchar(100) NOT NULL,
	`address` text,
	`phone` varchar(20),
	`email` varchar(320),
	`ownerId` int NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `health_centers_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `notifications` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`title` varchar(255) NOT NULL,
	`message` text,
	`type` enum('alert','info','success','error') NOT NULL DEFAULT 'info',
	`isRead` boolean NOT NULL DEFAULT false,
	`actionUrl` varchar(500),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `notifications_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `patient_records` (
	`id` int AUTO_INCREMENT NOT NULL,
	`healthCenterId` int NOT NULL,
	`recordedBy` int NOT NULL,
	`patientName` varchar(255) NOT NULL,
	`age` int NOT NULL,
	`sex` enum('Masculin','Féminin') NOT NULL,
	`region` varchar(100) NOT NULL,
	`primaryPathology` varchar(255) NOT NULL,
	`severity` enum('Légère','Modérée','Sévère') NOT NULL,
	`weight` decimal(5,2),
	`temperature` decimal(4,1),
	`systolicPressure` int,
	`diastolicPressure` int,
	`managementMode` varchar(100),
	`hospitalizationDays` int DEFAULT 0,
	`patientSatisfaction` int DEFAULT 0,
	`observations` text,
	`recordDate` datetime NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `patient_records_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
ALTER TABLE `users` MODIFY COLUMN `role` enum('user','admin','doctor','health_agent') NOT NULL DEFAULT 'user';--> statement-breakpoint
ALTER TABLE `users` ADD `phone` varchar(20);--> statement-breakpoint
ALTER TABLE `users` ADD `healthCenterId` int;--> statement-breakpoint
ALTER TABLE `users` ADD `isActive` boolean DEFAULT true NOT NULL;