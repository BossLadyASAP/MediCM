import DashboardLayout from "@/components/DashboardLayout";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useState } from "react";
import { Plus, Search, Trash2, Edit } from "lucide-react";

export default function Patients() {
  const [healthCenterId] = useState(1); // Default to first health center
  const [searchQuery, setSearchQuery] = useState("");
  const { data: patients, isLoading } = trpc.patient.list.useQuery({
    healthCenterId,
  });

  const filteredPatients = patients?.filter(
    (p) =>
      p.patientName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.region.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.primaryPathology.toLowerCase().includes(searchQuery.toLowerCase())
  ) || [];

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Patients</h1>
            <p className="text-muted-foreground mt-2">
              Gestion et suivi des dossiers patients
            </p>
          </div>
          <Button className="gap-2">
            <Plus className="w-4 h-4" />
            Nouveau patient
          </Button>
        </div>

        {/* Search */}
        <Card>
          <CardContent className="pt-6">
            <div className="flex gap-4">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-3 w-4 h-4 text-muted-foreground" />
                <Input
                  placeholder="Rechercher par nom, région ou pathologie..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Patients Table */}
        <Card>
          <CardHeader>
            <CardTitle>Liste des patients</CardTitle>
            <CardDescription>
              {filteredPatients.length} patient(s) trouvé(s)
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b">
                    <th className="text-left py-3 px-4 font-medium">Nom</th>
                    <th className="text-left py-3 px-4 font-medium">Âge</th>
                    <th className="text-left py-3 px-4 font-medium">Sexe</th>
                    <th className="text-left py-3 px-4 font-medium">Pathologie</th>
                    <th className="text-left py-3 px-4 font-medium">Sévérité</th>
                    <th className="text-left py-3 px-4 font-medium">Région</th>
                    <th className="text-left py-3 px-4 font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {isLoading ? (
                    <tr>
                      <td colSpan={7} className="text-center py-6 text-muted-foreground">
                        Chargement...
                      </td>
                    </tr>
                  ) : filteredPatients.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="text-center py-6 text-muted-foreground">
                        Aucun patient trouvé
                      </td>
                    </tr>
                  ) : (
                    filteredPatients.map((patient) => (
                      <tr key={patient.id} className="border-b hover:bg-muted/50">
                        <td className="py-3 px-4">{patient.patientName}</td>
                        <td className="py-3 px-4">{patient.age} ans</td>
                        <td className="py-3 px-4">{patient.sex}</td>
                        <td className="py-3 px-4">{patient.primaryPathology}</td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-1 rounded-full text-xs font-medium ${
                              patient.severity === "Sévère"
                                ? "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
                                : patient.severity === "Modérée"
                                  ? "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
                                  : "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
                            }`}
                          >
                            {patient.severity}
                          </span>
                        </td>
                        <td className="py-3 px-4">{patient.region}</td>
                        <td className="py-3 px-4 flex gap-2">
                          <Button variant="ghost" size="sm">
                            <Edit className="w-4 h-4" />
                          </Button>
                          <Button variant="ghost" size="sm" className="text-destructive">
                            <Trash2 className="w-4 h-4" />
                          </Button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
