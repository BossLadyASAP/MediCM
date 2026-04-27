import {
  int,
  mysqlEnum,
  mysqlTable,
  text,
  timestamp,
  varchar,
  decimal,
  boolean,
  datetime,
  json,
} from "drizzle-orm/mysql-core";

/**
 * Core user table backing auth flow with role-based access control.
 */
export const users = mysqlTable("users", {
  id: int("id").autoincrement().primaryKey(),
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  phone: varchar("phone", { length: 20 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin", "doctor", "health_agent"]).default("user").notNull(),
  healthCenterId: int("healthCenterId"),
  isActive: boolean("isActive").default(true).notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;

/**
 * Health centers table for multi-user organization support.
 */
export const healthCenters = mysqlTable("health_centers", {
  id: int("id").autoincrement().primaryKey(),
  name: varchar("name", { length: 255 }).notNull(),
  region: varchar("region", { length: 100 }).notNull(),
  address: text("address"),
  phone: varchar("phone", { length: 20 }),
  email: varchar("email", { length: 320 }),
  ownerId: int("ownerId").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type HealthCenter = typeof healthCenters.$inferSelect;
export type InsertHealthCenter = typeof healthCenters.$inferInsert;

/**
 * Patient records table - core epidemiological data collection.
 */
export const patientRecords = mysqlTable("patient_records", {
  id: int("id").autoincrement().primaryKey(),
  healthCenterId: int("healthCenterId").notNull(),
  recordedBy: int("recordedBy").notNull(),
  
  // Patient demographics
  patientName: varchar("patientName", { length: 255 }).notNull(),
  age: int("age").notNull(),
  sex: mysqlEnum("sex", ["Masculin", "Féminin"]).notNull(),
  
  // Location
  region: varchar("region", { length: 100 }).notNull(),
  
  // Clinical data
  primaryPathology: varchar("primaryPathology", { length: 255 }).notNull(),
  severity: mysqlEnum("severity", ["Légère", "Modérée", "Sévère"]).notNull(),
  
  // Vital signs
  weight: decimal("weight", { precision: 5, scale: 2 }),
  temperature: decimal("temperature", { precision: 4, scale: 1 }),
  systolicPressure: int("systolicPressure"),
  diastolicPressure: int("diastolicPressure"),
  
  // Management
  managementMode: varchar("managementMode", { length: 100 }),
  hospitalizationDays: int("hospitalizationDays").default(0),
  patientSatisfaction: int("patientSatisfaction").default(0), // 0-5 stars
  
  // Additional notes
  observations: text("observations"),
  
  // Metadata
  recordDate: datetime("recordDate").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type PatientRecord = typeof patientRecords.$inferSelect;
export type InsertPatientRecord = typeof patientRecords.$inferInsert;

/**
 * Analysis results table - stores AI-generated insights and statistics.
 */
export const analysisResults = mysqlTable("analysis_results", {
  id: int("id").autoincrement().primaryKey(),
  healthCenterId: int("healthCenterId").notNull(),
  analysisType: mysqlEnum("analysisType", ["descriptive", "ai_insights", "trend"]).notNull(),
  
  // Statistics snapshot
  totalPatients: int("totalPatients").default(0),
  femalePercentage: decimal("femalePercentage", { precision: 5, scale: 2 }),
  averageAge: decimal("averageAge", { precision: 5, scale: 2 }),
  averageTemperature: decimal("averageTemperature", { precision: 4, scale: 1 }),
  averageSatisfaction: decimal("averageSatisfaction", { precision: 3, scale: 2 }),
  severeCount: int("severeCount").default(0),
  
  // AI insights
  aiInsights: text("aiInsights"),
  aiModel: varchar("aiModel", { length: 50 }).default("claude-3-sonnet"),
  
  // Metadata
  generatedAt: timestamp("generatedAt").defaultNow().notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type AnalysisResult = typeof analysisResults.$inferSelect;
export type InsertAnalysisResult = typeof analysisResults.$inferInsert;

/**
 * Export history table - tracks data exports for audit trail.
 */
export const exportHistory = mysqlTable("export_history", {
  id: int("id").autoincrement().primaryKey(),
  healthCenterId: int("healthCenterId").notNull(),
  exportedBy: int("exportedBy").notNull(),
  exportType: mysqlEnum("exportType", ["csv", "pdf"]).notNull(),
  recordCount: int("recordCount").default(0),
  fileName: varchar("fileName", { length: 255 }),
  fileUrl: text("fileUrl"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type ExportHistory = typeof exportHistory.$inferSelect;
export type InsertExportHistory = typeof exportHistory.$inferInsert;

/**
 * Alerts table for severe cases and critical notifications.
 */
export const alerts = mysqlTable("alerts", {
  id: int("id").autoincrement().primaryKey(),
  healthCenterId: int("healthCenterId").notNull(),
  patientRecordId: int("patientRecordId"),
  alertType: mysqlEnum("alertType", ["severe_case", "critical_registration", "high_satisfaction_drop", "anomaly"]).notNull(),
  severity: mysqlEnum("severity", ["info", "warning", "critical"]).notNull(),
  title: varchar("title", { length: 255 }).notNull(),
  description: text("description"),
  isRead: boolean("isRead").default(false).notNull(),
  readBy: int("readBy"),
  readAt: timestamp("readAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type Alert = typeof alerts.$inferSelect;
export type InsertAlert = typeof alerts.$inferInsert;

/**
 * Audit log table for tracking user actions.
 */
export const auditLogs = mysqlTable("audit_logs", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull(),
  healthCenterId: int("healthCenterId"),
  action: varchar("action", { length: 100 }).notNull(),
  entityType: varchar("entityType", { length: 50 }).notNull(),
  entityId: int("entityId"),
  changes: json("changes"),
  ipAddress: varchar("ipAddress", { length: 45 }),
  userAgent: text("userAgent"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type AuditLog = typeof auditLogs.$inferSelect;
export type InsertAuditLog = typeof auditLogs.$inferInsert;

/**
 * Notifications table for system notifications.
 */
export const notifications = mysqlTable("notifications", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull(),
  title: varchar("title", { length: 255 }).notNull(),
  message: text("message"),
  type: mysqlEnum("type", ["alert", "info", "success", "error"]).default("info").notNull(),
  isRead: boolean("isRead").default(false).notNull(),
  actionUrl: varchar("actionUrl", { length: 500 }),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type Notification = typeof notifications.$inferSelect;
export type InsertNotification = typeof notifications.$inferInsert;
