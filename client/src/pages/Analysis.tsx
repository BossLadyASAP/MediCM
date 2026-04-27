import DashboardLayout from "@/components/DashboardLayout";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useState } from "react";
import { RefreshCw, Download, Filter } from "lucide-react";
import { Streamdown } from "streamdown";

export default function Analysis() {
  const [healthCenterId] = useState(1);
  const [showFilters, setShowFilters] = useState(false);
  const [filters, setFilters] = useState({
    startDate: "",
    endDate: "",
    region: "",
    pathology: "",
    severity: "",
  });
  
  const { data: stats } = trpc.analysis.getStats.useQuery({ healthCenterId });
  const { data: latestAnalysis } = trpc.analysis.getLatest.useQuery({ healthCenterId });
  const generateInsights = trpc.analysis.generateAIInsights.useMutation();

  const handleGenerateInsights = async () => {
    try {
      await generateInsights.mutateAsync({ healthCenterId });
    } catch (error) {
      console.error("Error generating insights:", error);
    }
  };

  const handleExportCSV = async () => {
    try {
      const response = await fetch('/api/trpc/analysis.exportCSV?input=' + JSON.stringify({ healthCenterId }));
      const data = await response.json();
      if (data.result?.data?.success && data.result?.data?.url) {
        window.open(data.result.data.url, "_blank");
      }
    } catch (error) {
      console.error("Error exporting CSV:", error);
    }
  };

  const handleExportPDF = async () => {
    try {
      const response = await fetch('/api/trpc/analysis.exportPDF?input=' + JSON.stringify({ healthCenterId }));
      const data = await response.json();
      if (data.result?.data?.success && data.result?.data?.url) {
        window.open(data.result.data.url, "_blank");
      }
    } catch (error) {
      console.error("Error exporting PDF:", error);
    }
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Analyses</h1>
            <p className="text-muted-foreground mt-2">
              Analyses épidémiologiques et insights IA
            </p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => setShowFilters(!showFilters)} className="gap-2">
              <Filter className="w-4 h-4" />
              Filtres
            </Button>
            <Button onClick={handleGenerateInsights} disabled={generateInsights.isPending} className="gap-2">
              <RefreshCw className={`w-4 h-4 ${generateInsights.isPending ? "animate-spin" : ""}`} />
              {generateInsights.isPending ? "Génération..." : "Générer insights IA"}
            </Button>
          </div>
        </div>

        {/* Advanced Filters */}
        {showFilters && (
          <Card>
            <CardHeader>
              <CardTitle>Filtres avancés</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
                <div>
                  <label className="text-sm font-medium">Date début</label>
                  <Input
                    type="date"
                    value={filters.startDate}
                    onChange={(e) => setFilters({ ...filters, startDate: e.target.value })}
                  />
                </div>
                <div>
                  <label className="text-sm font-medium">Date fin</label>
                  <Input
                    type="date"
                    value={filters.endDate}
                    onChange={(e) => setFilters({ ...filters, endDate: e.target.value })}
                  />
                </div>
                <div>
                  <label className="text-sm font-medium">Région</label>
                  <Select value={filters.region} onValueChange={(v) => setFilters({ ...filters, region: v })}>
                    <SelectTrigger>
                      <SelectValue placeholder="Toutes" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="">Toutes</SelectItem>
                      <SelectItem value="Centre">Centre</SelectItem>
                      <SelectItem value="Littoral">Littoral</SelectItem>
                      <SelectItem value="Ouest">Ouest</SelectItem>
                      <SelectItem value="Nord">Nord</SelectItem>
                      <SelectItem value="Sud">Sud</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <label className="text-sm font-medium">Pathologie</label>
                  <Select value={filters.pathology} onValueChange={(v) => setFilters({ ...filters, pathology: v })}>
                    <SelectTrigger>
                      <SelectValue placeholder="Toutes" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="">Toutes</SelectItem>
                      <SelectItem value="Paludisme">Paludisme</SelectItem>
                      <SelectItem value="Diarrhée">Diarrhée</SelectItem>
                      <SelectItem value="Pneumonie">Pneumonie</SelectItem>
                      <SelectItem value="Rougeole">Rougeole</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <label className="text-sm font-medium">Sévérité</label>
                  <Select value={filters.severity} onValueChange={(v) => setFilters({ ...filters, severity: v })}>
                    <SelectTrigger>
                      <SelectValue placeholder="Toutes" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="">Toutes</SelectItem>
                      <SelectItem value="Légère">Légère</SelectItem>
                      <SelectItem value="Modérée">Modérée</SelectItem>
                      <SelectItem value="Sévère">Sévère</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Statistics Summary */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium">Total patients</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats?.totalPatients || 0}</div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium">Âge moyen</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{(stats?.averageAge || 0).toFixed(1)} ans</div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium">Femmes</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{(stats?.femalePercentage || 0).toFixed(1)}%</div>
            </CardContent>
          </Card>
        </div>

        {/* AI Insights */}
        <Card>
          <CardHeader>
            <CardTitle>Insights IA - Analyse épidémiologique</CardTitle>
            <CardDescription>
              {latestAnalysis
                ? `Généré le ${new Date(latestAnalysis.generatedAt).toLocaleDateString("fr-FR")}`
                : "Aucune analyse disponible"}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {latestAnalysis && latestAnalysis.aiInsights ? (
              <div className="prose dark:prose-invert max-w-none">
                <Streamdown>{latestAnalysis.aiInsights}</Streamdown>
              </div>
            ) : (
              <p className="text-muted-foreground">
                Cliquez sur "Générer insights IA" pour créer une analyse.
              </p>
            )}
          </CardContent>
        </Card>

        {/* Export Options */}
        <Card>
          <CardHeader>
            <CardTitle>Exporter les données</CardTitle>
            <CardDescription>Télécharger les analyses en différents formats</CardDescription>
          </CardHeader>
          <CardContent className="flex gap-3">
            <Button variant="outline" className="gap-2" onClick={handleExportCSV}>
              <Download className="w-4 h-4" />
              Exporter CSV
            </Button>
            <Button variant="outline" className="gap-2" onClick={handleExportPDF}>
              <Download className="w-4 h-4" />
              Exporter PDF
            </Button>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
