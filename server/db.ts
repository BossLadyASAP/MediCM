import { eq, and, desc, gte, lte, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import {
  InsertUser,
  users,
  patientRecords,
  healthCenters,
  analysisResults,
  exportHistory,
  alerts,
  auditLogs,
  notifications,
  InsertAlert,
  InsertAuditLog,
  InsertNotification,
} from "../drizzle/schema";
import { ENV } from "./_core/env";

let _db: ReturnType<typeof drizzle> | null = null;

// Lazily create the drizzle instance so local tooling can run without a DB.
export async function getDb() {
  if (!_db && process.env.DATABASE_URL) {
    try {
      _db = drizzle(process.env.DATABASE_URL);
    } catch (error) {
      console.warn("[Database] Failed to connect:", error);
      _db = null;
    }
  }
  return _db;
}

export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) {
    throw new Error("User openId is required for upsert");
  }

  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot upsert user: database not available");
    return;
  }

  try {
    const values: InsertUser = {
      openId: user.openId,
    };
    const updateSet: Record<string, unknown> = {};

    const textFields = ["name", "email", "loginMethod"] as const;
    type TextField = (typeof textFields)[number];

    const assignNullable = (field: TextField) => {
      const value = user[field];
      if (value === undefined) return;
      const normalized = value ?? null;
      values[field] = normalized;
      updateSet[field] = normalized;
    };

    textFields.forEach(assignNullable);

    if (user.lastSignedIn !== undefined) {
      values.lastSignedIn = user.lastSignedIn;
      updateSet.lastSignedIn = user.lastSignedIn;
    }
    if (user.role !== undefined) {
      values.role = user.role;
      updateSet.role = user.role;
    } else if (user.openId === ENV.ownerOpenId) {
      values.role = "admin";
      updateSet.role = "admin";
    }

    if (!values.lastSignedIn) {
      values.lastSignedIn = new Date();
    }

    if (Object.keys(updateSet).length === 0) {
      updateSet.lastSignedIn = new Date();
    }

    await db.insert(users).values(values).onDuplicateKeyUpdate({
      set: updateSet,
    });
  } catch (error) {
    console.error("[Database] Failed to upsert user:", error);
    throw error;
  }
}

export async function getUserByOpenId(openId: string) {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get user: database not available");
    return undefined;
  }

  const result = await db
    .select()
    .from(users)
    .where(eq(users.openId, openId))
    .limit(1);

  return result.length > 0 ? result[0] : undefined;
}

export async function getAllUsers() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(users);
}

export async function updateUserRole(userId: number, role: string) {
  const db = await getDb();
  if (!db) return false;
  await db.update(users).set({ role: role as any }).where(eq(users.id, userId));
  return true;
}

export async function createHealthCenter(data: any) {
  const db = await getDb();
  if (!db) return null;
  const result = await db.insert(healthCenters).values(data);
  return result;
}

export async function getHealthCentersByUser(userId: number) {
  const db = await getDb();
  if (!db) return [];
  return db
    .select()
    .from(healthCenters)
    .where(eq(healthCenters.ownerId, userId));
}

export async function getHealthCenterById(id: number) {
  const db = await getDb();
  if (!db) return null;
  const result = await db
    .select()
    .from(healthCenters)
    .where(eq(healthCenters.id, id))
    .limit(1);
  return result.length > 0 ? result[0] : null;
}

export async function createPatientRecord(data: any) {
  const db = await getDb();
  if (!db) return null;
  const result = await db.insert(patientRecords).values(data);
  return result;
}

export async function getPatientRecordsByHealthCenter(healthCenterId: number) {
  const db = await getDb();
  if (!db) return [];
  return db
    .select()
    .from(patientRecords)
    .where(eq(patientRecords.healthCenterId, healthCenterId))
    .orderBy(desc(patientRecords.createdAt));
}

export async function searchPatientRecords(
  healthCenterId: number,
  query: string
) {
  const db = await getDb();
  if (!db) return [];
  return db
    .select()
    .from(patientRecords)
    .where(
      and(
        eq(patientRecords.healthCenterId, healthCenterId),
        sql`(patientName LIKE ${`%${query}%`} OR region LIKE ${`%${query}%`} OR primaryPathology LIKE ${`%${query}%`})`
      )
    );
}

export async function getPatientRecordById(id: number) {
  const db = await getDb();
  if (!db) return null;
  const result = await db
    .select()
    .from(patientRecords)
    .where(eq(patientRecords.id, id))
    .limit(1);
  return result.length > 0 ? result[0] : null;
}

export async function deletePatientRecord(id: number) {
  const db = await getDb();
  if (!db) return false;
  await db.delete(patientRecords).where(eq(patientRecords.id, id));
  return true;
}

export async function updatePatientRecord(id: number, data: any) {
  const db = await getDb();
  if (!db) return false;
  await db.update(patientRecords).set(data).where(eq(patientRecords.id, id));
  return true;
}

export async function calculateHealthCenterStats(healthCenterId: number) {
  const db = await getDb();
  if (!db) return null;

  const records = await db
    .select()
    .from(patientRecords)
    .where(eq(patientRecords.healthCenterId, healthCenterId));

  if (records.length === 0) {
    return {
      totalPatients: 0,
      femalePercentage: 0,
      averageAge: 0,
      averageTemperature: 0,
      averageSatisfaction: 0,
      severeCount: 0,
    };
  }

  const femaleCount = records.filter((r) => r.sex === "Féminin").length;
  const severeCount = records.filter((r) => r.severity === "Sévère").length;
  const avgAge =
    records.reduce((sum, r) => sum + r.age, 0) / records.length;
  const avgTemp =
    records.reduce((sum, r) => sum + (parseFloat(r.temperature as any) || 0), 0) /
    records.length;
  const avgSatisfaction =
    records.reduce((sum, r) => sum + (r.patientSatisfaction || 0), 0) /
    records.length;

  return {
    totalPatients: records.length,
    femalePercentage: (femaleCount / records.length) * 100,
    averageAge: avgAge,
    averageTemperature: avgTemp,
    averageSatisfaction: avgSatisfaction,
    severeCount,
  };
}

export async function createAnalysisResult(data: any) {
  const db = await getDb();
  if (!db) return null;
  const result = await db.insert(analysisResults).values(data);
  return result;
}

export async function getLatestAnalysis(healthCenterId: number) {
  const db = await getDb();
  if (!db) return null;
  const result = await db
    .select()
    .from(analysisResults)
    .where(eq(analysisResults.healthCenterId, healthCenterId))
    .orderBy(desc(analysisResults.createdAt))
    .limit(1);
  return result.length > 0 ? result[0] : null;
}

export async function createExportRecord(data: any) {
  const db = await getDb();
  if (!db) return null;
  const result = await db.insert(exportHistory).values(data);
  return result;
}

export async function getExportHistory(healthCenterId: number) {
  const db = await getDb();
  if (!db) return [];
  return db
    .select()
    .from(exportHistory)
    .where(eq(exportHistory.healthCenterId, healthCenterId))
    .orderBy(desc(exportHistory.createdAt));
}

export async function createAlert(data: InsertAlert) {
  const db = await getDb();
  if (!db) return null;
  const result = await db.insert(alerts).values(data);
  return result;
}

export async function getAlerts(healthCenterId: number, limit = 10) {
  const db = await getDb();
  if (!db) return [];
  return db
    .select()
    .from(alerts)
    .where(eq(alerts.healthCenterId, healthCenterId))
    .orderBy(desc(alerts.createdAt))
    .limit(limit);
}

export async function markAlertAsRead(alertId: number, userId: number) {
  const db = await getDb();
  if (!db) return false;
  await db
    .update(alerts)
    .set({ isRead: true, readBy: userId, readAt: new Date() })
    .where(eq(alerts.id, alertId));
  return true;
}

export async function createAuditLog(data: InsertAuditLog) {
  const db = await getDb();
  if (!db) return null;
  const result = await db.insert(auditLogs).values(data);
  return result;
}

export async function getAuditLogs(healthCenterId?: number, limit = 100) {
  const db = await getDb();
  if (!db) return [];
  const query = db.select().from(auditLogs);
  if (healthCenterId) {
    query.where(eq(auditLogs.healthCenterId, healthCenterId));
  }
  return query.orderBy(desc(auditLogs.createdAt)).limit(limit);
}

export async function createNotification(data: InsertNotification) {
  const db = await getDb();
  if (!db) return null;
  const result = await db.insert(notifications).values(data);
  return result;
}

export async function getUserNotifications(userId: number) {
  const db = await getDb();
  if (!db) return [];
  return db
    .select()
    .from(notifications)
    .where(eq(notifications.userId, userId))
    .orderBy(desc(notifications.createdAt));
}

export async function markNotificationAsRead(notificationId: number) {
  const db = await getDb();
  if (!db) return false;
  await db
    .update(notifications)
    .set({ isRead: true })
    .where(eq(notifications.id, notificationId));
  return true;
}
