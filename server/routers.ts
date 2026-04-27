import { z } from "zod";
import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { publicProcedure, router, protectedProcedure } from "./_core/trpc";
import {
  createHealthCenter,
  getHealthCentersByUser,
  getHealthCenterById,
  createPatientRecord,
  getPatientRecordsByHealthCenter,
  searchPatientRecords,
  getPatientRecordById,
  deletePatientRecord,
  updatePatientRecord,
  createAnalysisResult,
  getLatestAnalysis,
  createExportRecord,
  getExportHistory,
  calculateHealthCenterStats,
  getAllUsers,
  updateUserRole,
  createAlert,
  getAlerts,
  markAlertAsRead,
  createAuditLog,
  getAuditLogs,
  createNotification,
  getUserNotifications,
  markNotificationAsRead,
} from "./db";
import { invokeLLM } from "./_core/llm";
import { storagePut } from "./storage";

const adminProcedure = protectedProcedure.use(async ({ ctx, next }) => {
  if (ctx.user.role !== "admin") {
    throw new Error("Admin access required");
  }
  return next({ ctx });
});

export const appRouter = router({
  system: systemRouter,

  auth: router({
    me: publicProcedure.query((opts) => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return { success: true } as const;
    }),
  }),

  /**
   * ─── ADMIN PROCEDURES ───────────────────────────
   */
  admin: router({
    getAllUsers: adminProcedure.query(async () => {
      return getAllUsers();
    }),

    updateUserRole: adminProcedure
      .input(z.object({ userId: z.number(), role: z.string() }))
      .mutation(async ({ input }) => {
        await updateUserRole(input.userId, input.role);
        return { success: true };
      }),

    getAuditLogs: adminProcedure
      .input(z.object({ healthCenterId: z.number().optional(), limit: z.number().optional() }))
      .query(async ({ input }) => {
        return getAuditLogs(input.healthCenterId, input.limit);
      }),

    getDashboardStats: adminProcedure.query(async ({ ctx }) => {
      const healthCenters = await getHealthCentersByUser(ctx.user.id);
      const stats = await Promise.all(
        healthCenters.map((hc) => calculateHealthCenterStats(hc.id))
      );

      const totalPatients = stats.reduce((sum, s) => sum + (s?.totalPatients || 0), 0);
      const totalSevere = stats.reduce((sum, s) => sum + (s?.severeCount || 0), 0);
      const avgSatisfaction =
        stats.reduce((sum, s) => sum + (s?.averageSatisfaction || 0), 0) / stats.length || 0;

      return {
        totalPatients,
        totalSevere,
        avgSatisfaction,
        healthCenterCount: healthCenters.length,
      };
    }),
  }),

  /**
   * ─── HEALTH CENTER PROCEDURES ───────────────────────
   */
  healthCenter: router({
    create: protectedProcedure
      .input(
        z.object({
          name: z.string().min(1),
          region: z.string().min(1),
          address: z.string().optional(),
          phone: z.string().optional(),
          email: z.string().email().optional(),
        })
      )
      .mutation(async ({ input, ctx }) => {
        await createHealthCenter({
          name: input.name,
          region: input.region,
          address: input.address || null,
          phone: input.phone || null,
          email: input.email || null,
          ownerId: ctx.user.id,
        });
        await createAuditLog({
          userId: ctx.user.id,
          action: "CREATE",
          entityType: "health_center",
          changes: input,
        });
        return { success: true };
      }),

    list: protectedProcedure.query(async ({ ctx }) => {
      return getHealthCentersByUser(ctx.user.id);
    }),

    get: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return getHealthCenterById(input.id);
      }),

    getStats: protectedProcedure
      .input(z.object({ healthCenterId: z.number() }))
      .query(async ({ input }) => {
        return calculateHealthCenterStats(input.healthCenterId);
      }),
  }),

  /**
   * ─── PATIENT RECORD PROCEDURES ──────────────────────
   */
  patient: router({
    create: protectedProcedure
      .input(
        z.object({
          healthCenterId: z.number(),
          patientName: z.string().min(1),
          age: z.number().min(0).max(150),
          sex: z.enum(["Masculin", "Féminin"]),
          region: z.string().min(1),
          primaryPathology: z.string().min(1),
          severity: z.enum(["Légère", "Modérée", "Sévère"]),
          weight: z.number().optional(),
          temperature: z.number().optional(),
          systolicPressure: z.number().optional(),
          diastolicPressure: z.number().optional(),
          managementMode: z.string().optional(),
          hospitalizationDays: z.number().optional(),
          patientSatisfaction: z.number().min(0).max(5).optional(),
          observations: z.string().optional(),
        })
      )
      .mutation(async ({ input, ctx }) => {
        await createPatientRecord({
          healthCenterId: input.healthCenterId,
          recordedBy: ctx.user.id,
          patientName: input.patientName,
          age: input.age,
          sex: input.sex,
          region: input.region,
          primaryPathology: input.primaryPathology,
          severity: input.severity,
          weight: input.weight ? input.weight.toString() : null,
          temperature: input.temperature ? input.temperature.toString() : null,
          systolicPressure: input.systolicPressure || null,
          diastolicPressure: input.diastolicPressure || null,
          managementMode: input.managementMode || null,
          hospitalizationDays: input.hospitalizationDays || 0,
          patientSatisfaction: input.patientSatisfaction || 0,
          observations: input.observations || null,
          recordDate: new Date(),
        });

        // Create alert for severe cases
        if (input.severity === "Sévère") {
          await createAlert({
            healthCenterId: input.healthCenterId,
            alertType: "severe_case",
            severity: "critical",
            title: `Cas sévère: ${input.patientName}`,
            description: `Patient ${input.patientName}, ${input.age} ans, pathologie: ${input.primaryPathology}`,
          });
        }

        await createAuditLog({
          userId: ctx.user.id,
          healthCenterId: input.healthCenterId,
          action: "CREATE",
          entityType: "patient_record",
          changes: input,
        });

        return { success: true };
      }),

    list: protectedProcedure
      .input(z.object({ healthCenterId: z.number() }))
      .query(async ({ input }) => {
        return getPatientRecordsByHealthCenter(input.healthCenterId);
      }),

    search: protectedProcedure
      .input(z.object({ healthCenterId: z.number(), query: z.string() }))
      .query(async ({ input }) => {
        return searchPatientRecords(input.healthCenterId, input.query);
      }),

    get: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return getPatientRecordById(input.id);
      }),

    delete: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const record = await getPatientRecordById(input.id);
        if (record) {
          await createAuditLog({
            userId: ctx.user.id,
            healthCenterId: record.healthCenterId,
            action: "DELETE",
            entityType: "patient_record",
            entityId: input.id,
          });
        }
        await deletePatientRecord(input.id);
        return { success: true };
      }),

    update: protectedProcedure
      .input(
        z.object({
          id: z.number(),
          patientName: z.string().optional(),
          severity: z.enum(["Légère", "Modérée", "Sévère"]).optional(),
          patientSatisfaction: z.number().optional(),
          observations: z.string().optional(),
        })
      )
      .mutation(async ({ input, ctx }) => {
        const { id, ...data } = input;
        const record = await getPatientRecordById(id);
        if (record) {
          await createAuditLog({
            userId: ctx.user.id,
            healthCenterId: record.healthCenterId,
            action: "UPDATE",
            entityType: "patient_record",
            entityId: id,
            changes: data,
          });
        }
        await updatePatientRecord(id, data);
        return { success: true };
      }),
  }),

  /**
   * ─── ANALYSIS PROCEDURES ────────────────────────────
   */
  analysis: router({
    getStats: protectedProcedure
      .input(z.object({ healthCenterId: z.number() }))
      .query(async ({ input }) => {
        return calculateHealthCenterStats(input.healthCenterId);
      }),

    generateAIInsights: protectedProcedure
      .input(z.object({ healthCenterId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const stats = await calculateHealthCenterStats(input.healthCenterId);
        if (!stats || stats.totalPatients === 0) {
          return { success: false, message: "No data available for analysis" };
        }

        const prompt = `Based on the following epidemiological health data from a health center in Cameroon, provide a concise clinical analysis and recommendations:

Total Patients: ${stats.totalPatients}
Female Percentage: ${stats.femalePercentage.toFixed(1)}%
Average Age: ${stats.averageAge.toFixed(1)} years
Average Temperature: ${stats.averageTemperature.toFixed(1)}°C
Average Patient Satisfaction: ${stats.averageSatisfaction.toFixed(1)}/5
Severe Cases: ${stats.severeCount}

Please provide:
1. Key health trends observed
2. Risk factors and vulnerable populations
3. Recommendations for clinical management
4. Suggested interventions

Format your response in clear sections with actionable insights.`;

        try {
          const response = await invokeLLM({
            messages: [
              {
                role: "system",
                content:
                  "You are a clinical epidemiologist analyzing health surveillance data from Cameroon. Provide evidence-based insights and recommendations.",
              },
              { role: "user", content: prompt },
            ],
          });

          const content = response.choices[0]?.message.content;
          const aiInsights = typeof content === "string" ? content : "Analysis unavailable";

          await createAnalysisResult({
            healthCenterId: input.healthCenterId,
            analysisType: "ai_insights",
            totalPatients: stats.totalPatients,
            femalePercentage: stats.femalePercentage.toString(),
            averageAge: stats.averageAge.toString(),
            averageTemperature: stats.averageTemperature.toString(),
            averageSatisfaction: stats.averageSatisfaction.toString(),
            severeCount: stats.severeCount,
            aiInsights,
            aiModel: "claude-3-sonnet",
          });

          await createAuditLog({
            userId: ctx.user.id,
            healthCenterId: input.healthCenterId,
            action: "GENERATE_ANALYSIS",
            entityType: "analysis",
          });

          return { success: true, insights: aiInsights };
        } catch (error) {
          console.error("AI analysis error:", error);
          return { success: false, message: "Failed to generate AI insights" };
        }
      }),

    getLatest: protectedProcedure
      .input(z.object({ healthCenterId: z.number() }))
      .query(async ({ input }) => {
        return getLatestAnalysis(input.healthCenterId);
      }),

    exportCSV: protectedProcedure
      .input(z.object({ healthCenterId: z.number() }))
      .query(async ({ input, ctx }) => {
        try {
          const records = await getPatientRecordsByHealthCenter(input.healthCenterId);
          let csv = 'Nom,Age,Sexe,Region,Pathologie,Severite,Temperature,Satisfaction\n';
          records.forEach((r: any) => {
            csv += `"${r.patientName}",${r.age},${r.sex},${r.region},${r.primaryPathology},${r.severity},${r.temperature},${r.patientSatisfaction}\n`;
          });
          const buffer = Buffer.from(csv, 'utf-8');
          const { url } = await storagePut(`analysis-export-${Date.now()}.csv`, buffer, 'text/csv');
          await createExportRecord({
            healthCenterId: input.healthCenterId,
            exportedBy: ctx.user.id,
            exportType: 'csv',
            recordCount: records.length,
            fileName: `analysis-export-${Date.now()}.csv`,
            fileUrl: url,
          });
          return { success: true, url };
        } catch (error) {
          console.error('CSV export error:', error);
          return { success: false, message: 'Failed to export CSV' };
        }
      }),

    exportPDF: protectedProcedure
      .input(z.object({ healthCenterId: z.number() }))
      .query(async ({ input, ctx }) => {
        try {
          const records = await getPatientRecordsByHealthCenter(input.healthCenterId);
          const stats = await calculateHealthCenterStats(input.healthCenterId);
          let pdfContent = 'Health Center Analysis Report\n\n';
          pdfContent += `Total Patients: ${stats?.totalPatients || 0}\n`;
          pdfContent += `Female Percentage: ${stats?.femalePercentage.toFixed(1) || 0}%\n`;
          pdfContent += `Average Age: ${stats?.averageAge.toFixed(1) || 0}\n`;
          pdfContent += `Severe Cases: ${stats?.severeCount || 0}\n\n`;
          pdfContent += 'Patient Records:\n';
          records.forEach((r: any) => {
            pdfContent += `- ${r.patientName} (${r.age}y, ${r.sex}): ${r.primaryPathology} (${r.severity})\n`;
          });
          const buffer = Buffer.from(pdfContent, 'utf-8');
          const { url } = await storagePut(`analysis-export-${Date.now()}.pdf`, buffer, 'application/pdf');
          await createExportRecord({
            healthCenterId: input.healthCenterId,
            exportedBy: ctx.user.id,
            exportType: 'pdf',
            recordCount: records.length,
            fileName: `analysis-export-${Date.now()}.pdf`,
            fileUrl: url,
          });
          return { success: true, url };
        } catch (error) {
          console.error('PDF export error:', error);
          return { success: false, message: 'Failed to export PDF' };
        }
      }),
  }),

  /**
   * ─── ALERTS PROCEDURES ──────────────────────────────
   */
  alerts: router({
    list: protectedProcedure
      .input(z.object({ healthCenterId: z.number() }))
      .query(async ({ input }) => {
        return getAlerts(input.healthCenterId);
      }),

    markAsRead: protectedProcedure
      .input(z.object({ alertId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        await markAlertAsRead(input.alertId, ctx.user.id);
        return { success: true };
      }),
  }),

  /**
   * ─── NOTIFICATIONS PROCEDURES ───────────────────────
   */
  notifications: router({
    list: protectedProcedure.query(async ({ ctx }) => {
      return getUserNotifications(ctx.user.id);
    }),

    markAsRead: protectedProcedure
      .input(z.object({ notificationId: z.number() }))
      .mutation(async ({ input }) => {
        await markNotificationAsRead(input.notificationId);
        return { success: true };
      }),
  }),

  /**
   * ─── EXPORT PROCEDURES ──────────────────────────────
   */
  export: router({
    generateCSV: protectedProcedure
      .input(z.object({ healthCenterId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const records = await getPatientRecordsByHealthCenter(
          input.healthCenterId
        );

        if (records.length === 0) {
          return { success: false, message: "No records to export" };
        }

        // Generate CSV content
        const headers = [
          "Patient Name",
          "Age",
          "Sex",
          "Region",
          "Pathology",
          "Severity",
          "Weight (kg)",
          "Temperature (°C)",
          "Systolic BP",
          "Diastolic BP",
          "Management Mode",
          "Hospitalization Days",
          "Satisfaction",
          "Record Date",
        ];

        const rows = records.map((r) => [
          r.patientName,
          r.age,
          r.sex,
          r.region,
          r.primaryPathology,
          r.severity,
          r.weight || "",
          r.temperature || "",
          r.systolicPressure || "",
          r.diastolicPressure || "",
          r.managementMode || "",
          r.hospitalizationDays || 0,
          r.patientSatisfaction || 0,
          new Date(r.recordDate).toLocaleDateString("fr-FR"),
        ]);

        const csvContent =
          headers.join(",") +
          "\n" +
          rows.map((row) => row.map((cell) => `"${cell}"`).join(",")).join("\n");

        const fileName = `medicm_export_${new Date().toISOString().split("T")[0]}.csv`;
        const buffer = Buffer.from(csvContent, "utf-8");

        const { url } = await storagePut(
          `exports/${ctx.user.id}/${fileName}`,
          buffer,
          "text/csv"
        );

        await createExportRecord({
          healthCenterId: input.healthCenterId,
          exportedBy: ctx.user.id,
          exportType: "csv",
          recordCount: records.length,
          fileName,
          fileUrl: url,
        });

        await createAuditLog({
          userId: ctx.user.id,
          healthCenterId: input.healthCenterId,
          action: "EXPORT",
          entityType: "patient_records",
          changes: { format: "csv", recordCount: records.length },
        });

        return { success: true, url, fileName };
      }),

    getHistory: protectedProcedure
      .input(z.object({ healthCenterId: z.number() }))
      .query(async ({ input }) => {
        return getExportHistory(input.healthCenterId);
      }),
  }),
});

export type AppRouter = typeof appRouter;
