import DashboardLayout from "@/components/DashboardLayout";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import { TrendingUp, Users, AlertTriangle, Smile } from "lucide-react";

const COLORS = ["#0ea5e9", "#10b981", "#f59e0b", "#ef4444"];

export default function Dashboard() {
  const { data: stats, isLoading } = trpc.admin.getDashboardStats.useQuery();
  const { data: alerts } = trpc.alerts.list.useQuery({ healthCenterId: 1 });

  // Mock data for charts
  const timeSeriesData = [
    { date: "Lun", patients: 24, severe: 4 },
    { date: "Mar", patients: 13, severe: 3 },
    { date: "Mer", patients: 22, severe: 5 },
    { date: "Jeu", patients: 39, severe: 8 },
    { date: "Ven", patients: 29, severe: 6 },
    { date: "Sam", patients: 43, severe: 9 },
    { date: "Dim", patients: 18, severe: 3 },
  ];

  const pathologyData = [
    { name: "Paludisme", value: 35 },
    { name: "Diarrhée", value: 25 },
    { name: "Grippe", value: 20 },
    { name: "Autres", value: 20 },
  ];

  const genderData = [
    { name: "Masculin", value: 55 },
    { name: "Féminin", value: 45 },
  ];

  const severityData = [
    { name: "Légère", value: 60 },
    { name: "Modérée", value: 30 },
    { name: "Sévère", value: 10 },
  ];

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Tableau de bord</h1>
          <p className="text-muted-foreground mt-2">
            Bienvenue sur MedicM Pro - Gestion médicale avancée
          </p>
        </div>

        {/* KPI Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Total Patients */}
          <Card className="border-l-4 border-l-blue-500 hover:shadow-lg transition-shadow">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Patients Total
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-end justify-between">
                <div>
                  {isLoading ? (
                    <Skeleton className="h-8 w-16" />
                  ) : (
                    <div className="text-2xl font-bold">{stats?.totalPatients || 0}</div>
                  )}
                  <p className="text-xs text-green-600 mt-1 flex items-center gap-1">
                    <TrendingUp className="w-3 h-3" /> +12% ce mois
                  </p>
                </div>
                <Users className="w-8 h-8 text-blue-500 opacity-20" />
              </div>
            </CardContent>
          </Card>

          {/* Severe Cases */}
          <Card className="border-l-4 border-l-red-500 hover:shadow-lg transition-shadow">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Cas Sévères
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-end justify-between">
                <div>
                  {isLoading ? (
                    <Skeleton className="h-8 w-16" />
                  ) : (
                    <div className="text-2xl font-bold">{stats?.totalSevere || 0}</div>
                  )}
                  <p className="text-xs text-red-600 mt-1 flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3" /> Attention requise
                  </p>
                </div>
                <AlertTriangle className="w-8 h-8 text-red-500 opacity-20" />
              </div>
            </CardContent>
          </Card>

          {/* Satisfaction Rate */}
          <Card className="border-l-4 border-l-green-500 hover:shadow-lg transition-shadow">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Satisfaction
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-end justify-between">
                <div>
                  {isLoading ? (
                    <Skeleton className="h-8 w-16" />
                  ) : (
                    <div className="text-2xl font-bold">
                      {(stats?.avgSatisfaction || 0).toFixed(1)}/5
                    </div>
                  )}
                  <p className="text-xs text-green-600 mt-1 flex items-center gap-1">
                    <TrendingUp className="w-3 h-3" /> Excellente
                  </p>
                </div>
                <Smile className="w-8 h-8 text-green-500 opacity-20" />
              </div>
            </CardContent>
          </Card>

          {/* Health Centers */}
          <Card className="border-l-4 border-l-cyan-500 hover:shadow-lg transition-shadow">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Centres de Santé
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-end justify-between">
                <div>
                  {isLoading ? (
                    <Skeleton className="h-8 w-16" />
                  ) : (
                    <div className="text-2xl font-bold">{stats?.healthCenterCount || 0}</div>
                  )}
                  <p className="text-xs text-cyan-600 mt-1">Actifs</p>
                </div>
                <div className="w-8 h-8 text-cyan-500 opacity-20 text-lg">🏥</div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Charts Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Time Series Chart */}
          <Card>
            <CardHeader>
              <CardTitle>Évolution des patients</CardTitle>
              <CardDescription>Derniers 7 jours</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={timeSeriesData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="date" />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Line
                    type="monotone"
                    dataKey="patients"
                    stroke="#0ea5e9"
                    name="Total patients"
                  />
                  <Line
                    type="monotone"
                    dataKey="severe"
                    stroke="#ef4444"
                    name="Cas sévères"
                  />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          {/* Pathology Distribution */}
          <Card>
            <CardHeader>
              <CardTitle>Distribution par pathologie</CardTitle>
              <CardDescription>Répartition des cas</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={pathologyData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, value }) => `${name}: ${value}%`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {pathologyData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          {/* Gender Distribution */}
          <Card>
            <CardHeader>
              <CardTitle>Répartition par genre</CardTitle>
              <CardDescription>Hommes vs Femmes</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={genderData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="value" fill="#10b981" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          {/* Severity Distribution */}
          <Card>
            <CardHeader>
              <CardTitle>Répartition par sévérité</CardTitle>
              <CardDescription>Cas légers, modérés et sévères</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={severityData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="value" fill="#f59e0b" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </div>

        {/* Recent Alerts */}
        <Card>
          <CardHeader>
            <CardTitle>Alertes récentes</CardTitle>
            <CardDescription>Cas critiques et notifications</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {alerts && alerts.length > 0 ? (
                alerts.slice(0, 5).map((alert) => (
                  <div
                    key={alert.id}
                    className={`p-3 rounded-lg border-l-4 ${
                      alert.severity === "critical"
                        ? "border-l-red-500 bg-red-50 dark:bg-red-950"
                        : alert.severity === "warning"
                          ? "border-l-yellow-500 bg-yellow-50 dark:bg-yellow-950"
                          : "border-l-blue-500 bg-blue-50 dark:bg-blue-950"
                    }`}
                  >
                    <p className="font-medium text-sm">{alert.title}</p>
                    <p className="text-xs text-muted-foreground mt-1">{alert.description}</p>
                  </div>
                ))
              ) : (
                <p className="text-sm text-muted-foreground">Aucune alerte</p>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
