import { useMemo } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
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
import {
  Users,
  AlertTriangle,
  TrendingUp,
  Building2,
  Activity,
} from "lucide-react";

const DEMO_COLORS = {
  primary: "#0066CC",
  success: "#00AA44",
  warning: "#FF9900",
  danger: "#FF3333",
  light: "#F0F4F8",
};

export default function DemoDashboard() {
  // Demo data
  const demoStats = useMemo(
    () => ({
      totalPatients: 1247,
      severeCases: 23,
      satisfactionRate: 4.7,
      activeCenters: 12,
      patientsGrowth: 12,
      casesGrowth: -5,
      satisfactionGrowth: 8,
      centersGrowth: 2,
    }),
    []
  )

  const patientEvolutionData = [
    { day: "Lun", total: 45, severe: 3 },
    { day: "Mar", total: 52, severe: 4 },
    { day: "Mer", total: 48, severe: 2 },
    { day: "Jeu", total: 61, severe: 5 },
    { day: "Ven", total: 55, severe: 3 },
    { day: "Sam", total: 42, severe: 2 },
    { day: "Dim", total: 38, severe: 4 },
  ];

  const pathologyData = [
    { name: "Hypertension", value: 320, color: DEMO_COLORS.danger },
    { name: "Diabète", value: 280, color: DEMO_COLORS.warning },
    { name: "Malaria", value: 210, color: DEMO_COLORS.warning },
    { name: "Infections", value: 190, color: "#FF6B6B" },
    { name: "Autres", value: 247, color: DEMO_COLORS.light },
  ];

  const genderData = [
    { name: "Hommes", value: 620, color: DEMO_COLORS.primary },
    { name: "Femmes", value: 627, color: "#FF69B4" },
  ];

  const regionData = [
    { region: "Centre", patients: 320 },
    { region: "Littoral", patients: 280 },
    { region: "Ouest", patients: 210 },
    { region: "Nord-Ouest", patients: 190 },
    { region: "Sud-Ouest", patients: 140 },
    { region: "Est", patients: 107 },
  ];

  const recentAlerts = [
    {
      id: 1,
      patient: "Marie Dupont",
      severity: "Sévère",
      pathology: "Hypertension",
      time: "Il y a 2 heures",
    },
    {
      id: 2,
      patient: "Jean Martin",
      severity: "Modérée",
      pathology: "Diabète",
      time: "Il y a 4 heures",
    },
    {
      id: 3,
      patient: "Anne Leclerc",
      severity: "Sévère",
      pathology: "Malaria",
      time: "Il y a 6 heures",
    },
    {
      id: 4,
      patient: "Pierre Moreau",
      severity: "Légère",
      pathology: "Infection",
      time: "Il y a 8 heures",
    },
  ];

  const StatCard = ({
    icon: Icon,
    label,
    value,
    trend,
    color,
  }: {
    icon: React.ComponentType<{ className: string }>;
    label: string;
    value: string | number;
    trend: number;
    color: string;
  }) => (
    <Card className="p-6 border-l-4" style={{ borderLeftColor: color }}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm font-medium text-slate-600 dark:text-slate-400">
            {label}
          </p>
          <p className="text-3xl font-bold text-slate-900 dark:text-white mt-2">
            {value}
          </p>
          <p className={`text-sm mt-2 ${trend >= 0 ? "text-green-600" : "text-red-600"}`}>
            {trend >= 0 ? "↑" : "↓"} {Math.abs(trend)}% ce mois
          </p>
        </div>
        <div style={{ color }}>
          <Icon className="w-8 h-8" />
        </div>
      </div>
    </Card>
  );

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "Sévère":
        return "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200";
      case "Modérée":
        return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200";
      case "Légère":
        return "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200";
      default:
        return "bg-gray-100 text-gray-800";
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-slate-900 dark:text-white">
          Tableau de Bord - Mode Démo
        </h1>
        <p className="text-slate-600 dark:text-slate-400 mt-2">
          Explorez les fonctionnalités complètes de MedicM Pro avec des données
          de démonstration
        </p>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          icon={Users}
          label="Patients Total"
          value={demoStats.totalPatients}
          trend={demoStats.patientsGrowth}
          color={DEMO_COLORS.primary}
        />
        <StatCard
          icon={AlertTriangle}
          label="Cas Sévères"
          value={demoStats.severeCases}
          trend={demoStats.casesGrowth}
          color={DEMO_COLORS.danger}
        />
        <StatCard
          icon={TrendingUp}
          label="Satisfaction"
          value={`${demoStats.satisfactionRate}/5`}
          trend={demoStats.satisfactionGrowth}
          color={DEMO_COLORS.success}
        />
        <StatCard
          icon={Building2}
          label="Centres Actifs"
          value={demoStats.activeCenters}
          trend={demoStats.centersGrowth}
          color={DEMO_COLORS.warning}
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Patient Evolution */}
        <Card className="p-6">
          <h2 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">
            Évolution des Patients
          </h2>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={patientEvolutionData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="day" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Line
                type="monotone"
                dataKey="total"
                stroke={DEMO_COLORS.primary}
                name="Total patients"
                strokeWidth={2}
              />
              <Line
                type="monotone"
                dataKey="severe"
                stroke={DEMO_COLORS.danger}
                name="Cas sévères"
                strokeWidth={2}
              />
            </LineChart>
          </ResponsiveContainer>
        </Card>

        {/* Pathology Distribution */}
        <Card className="p-6">
          <h2 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">
            Distribution par Pathologie
          </h2>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={pathologyData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, value }) => `${name}: ${value}`}
                outerRadius={100}
                fill="#8884d8"
                dataKey="value"
              >
                {pathologyData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </Card>

        {/* Gender Distribution */}
        <Card className="p-6">
          <h2 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">
            Distribution par Genre
          </h2>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={genderData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, value }) => `${name}: ${value}`}
                outerRadius={100}
                fill="#8884d8"
                dataKey="value"
              >
                {genderData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </Card>

        {/* Regional Distribution */}
        <Card className="p-6">
          <h2 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">
            Distribution par Région
          </h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={regionData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="region" />
              <YAxis />
              <Tooltip />
              <Bar dataKey="patients" fill={DEMO_COLORS.primary} />
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </div>

      {/* Recent Alerts */}
      <Card className="p-6">
        <h2 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">
          Alertes Récentes
        </h2>
        <div className="space-y-3">
          {recentAlerts.map((alert) => (
            <div
              key={alert.id}
              className="flex items-center justify-between p-4 border border-slate-200 dark:border-slate-700 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
            >
              <div className="flex-1">
                <p className="font-medium text-slate-900 dark:text-white">
                  {alert.patient}
                </p>
                <p className="text-sm text-slate-600 dark:text-slate-400">
                  {alert.pathology} • {alert.time}
                </p>
              </div>
              <Badge className={getSeverityColor(alert.severity)}>
                {alert.severity}
              </Badge>
            </div>
          ))}
        </div>
      </Card>

      {/* Demo Info */}
      <Card className="p-6 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800">
        <p className="text-sm text-blue-800 dark:text-blue-300">
          <strong>Mode Démo :</strong> Cet espace affiche des données de
          démonstration. Pour accéder aux données réelles et gérer votre centre
          de santé, veuillez vous inscrire ou vous connecter.
        </p>
      </Card>
    </div>
  );
}
