import DashboardLayout from "@/components/DashboardLayout";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useState } from "react";
import { Download, Eye, EyeOff, AlertCircle } from "lucide-react";
import { useAuth } from "@/_core/hooks/useAuth";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

export default function Settings() {
  const { isDemoMode } = useAuth();
  const { data: auditLogs, isLoading: auditLoading } = trpc.admin.getAuditLogs.useQuery({
    limit: 50,
  });
  const { data: exportHistory } = trpc.export.getHistory.useQuery({ healthCenterId: 1 });
  const [showDetails, setShowDetails] = useState<Record<number, boolean>>({});

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Paramètres</h1>
          <p className="text-muted-foreground mt-2">
            Configuration et audit de l'application
          </p>
        </div>

        {isDemoMode && (
          <Alert variant="default" className="bg-blue-50 border-blue-200 dark:bg-blue-900/20 dark:border-blue-800">
            <AlertCircle className="h-4 w-4 text-blue-600 dark:text-blue-400" />
            <AlertTitle className="text-blue-800 dark:text-blue-300">Mode Démo</AlertTitle>
            <AlertDescription className="text-blue-700 dark:text-blue-400">
              En mode démo, vous pouvez consulter l'historique mais la modification des paramètres est désactivée.
            </AlertDescription>
          </Alert>
        )}

        {/* Tabs */}
        <Tabs defaultValue="audit" className="w-full">
          <TabsList>
            <TabsTrigger value="audit">Journal d'audit</TabsTrigger>
            <TabsTrigger value="exports">Historique d'export</TabsTrigger>
            <TabsTrigger value="general">Configuration générale</TabsTrigger>
          </TabsList>

          {/* Audit Log Tab */}
          <TabsContent value="audit" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Journal d'audit</CardTitle>
                <CardDescription>
                  Historique de toutes les actions effectuées dans le système
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3 max-h-96 overflow-y-auto">
                  {auditLoading ? (
                    <p className="text-muted-foreground">Chargement...</p>
                  ) : auditLogs && auditLogs.length > 0 ? (
                        (auditLogs as any[]).map((log) => (
                      <div
                        key={log.id}
                        className="p-3 border rounded-lg hover:bg-muted/50 transition-colors"
                      >
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <p className="font-medium text-sm">
                              {log.action} - {log.entityType}
                            </p>
                            <p className="text-xs text-muted-foreground mt-1">
                              {new Date(log.createdAt).toLocaleString("fr-FR")}
                            </p>
                          </div>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() =>
                              setShowDetails((prev) => ({
                                ...prev,
                                [log.id]: !prev[log.id],
                              }))
                            }
                          >
                            {showDetails[log.id] ? (
                              <EyeOff className="w-4 h-4" />
                            ) : (
                              <Eye className="w-4 h-4" />
                            )}
                          </Button>
                        </div>
                        {showDetails[log.id] && log.changes && (
                          <pre className="mt-2 p-2 bg-muted rounded text-xs overflow-x-auto">
                            {JSON.stringify(log.changes, null, 2)}
                          </pre>
                        )}
                      </div>
                    ))
                  ) : (
                    <p className="text-muted-foreground text-center py-6">
                      Aucun audit disponible
                    </p>
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Export History Tab */}
          <TabsContent value="exports" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Historique d'export</CardTitle>
                <CardDescription>
                  Liste de tous les exports de données effectués
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b">
                        <th className="text-left py-3 px-4 font-medium">Fichier</th>
                        <th className="text-left py-3 px-4 font-medium">Format</th>
                        <th className="text-left py-3 px-4 font-medium">Enregistrements</th>
                        <th className="text-left py-3 px-4 font-medium">Date</th>
                        <th className="text-left py-3 px-4 font-medium">Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {exportHistory && exportHistory.length > 0 ? (
                        exportHistory.map((exp) => (
                          <tr key={exp.id} className="border-b hover:bg-muted/50">
                            <td className="py-3 px-4">{exp.fileName}</td>
                            <td className="py-3 px-4">
                              <span className="px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                                {exp.exportType.toUpperCase()}
                              </span>
                            </td>
                            <td className="py-3 px-4">{exp.recordCount}</td>
                            <td className="py-3 px-4">
                              {new Date(exp.createdAt).toLocaleDateString("fr-FR")}
                            </td>
                            <td className="py-3 px-4">
                              <Button variant="ghost" size="sm" className="gap-2">
                                <Download className="w-4 h-4" />
                                Télécharger
                              </Button>
                            </td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan={5} className="text-center py-6 text-muted-foreground">
                            Aucun export disponible
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* General Settings Tab */}
          <TabsContent value="general" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Configuration générale</CardTitle>
                <CardDescription>
                  Paramètres globaux de l'application
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div>
                  <label className="text-sm font-medium">Nom de l'application</label>
                  <input
                    type="text"
                    value="MedicM Pro"
                    className="mt-2 w-full px-3 py-2 border rounded-lg bg-muted"
                    disabled
                  />
                </div>

                <div>
                  <label className="text-sm font-medium">Version</label>
                  <input
                    type="text"
                    value="1.0.0"
                    className="mt-2 w-full px-3 py-2 border rounded-lg bg-muted"
                    disabled
                  />
                </div>

                <div>
                  <label className="text-sm font-medium">Langue</label>
                  <select className="mt-2 w-full px-3 py-2 border rounded-lg" disabled={isDemoMode}>
                    <option>Français</option>
                    <option>English</option>
                  </select>
                </div>

                <Button disabled={isDemoMode}>
                  {isDemoMode ? "Modification désactivée" : "Enregistrer les modifications"}
                </Button>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </DashboardLayout>
  );
}
