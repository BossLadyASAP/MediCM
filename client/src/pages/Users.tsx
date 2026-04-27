import DashboardLayout from "@/components/DashboardLayout";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useState } from "react";
import { Shield, User, UserCheck, AlertCircle } from "lucide-react";
import { useAuth } from "@/_core/hooks/useAuth";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

export default function Users() {
  const { isDemoMode } = useAuth();
  const { data: users, isLoading } = trpc.admin.getAllUsers.useQuery();
  const updateRole = trpc.admin.updateUserRole.useMutation();
  const [selectedRole, setSelectedRole] = useState<Record<number, string>>({});

  const handleRoleChange = async (userId: number, newRole: string) => {
    if (isDemoMode) return;
    try {
      await updateRole.mutateAsync({ userId, role: newRole });
      setSelectedRole((prev) => ({ ...prev, [userId]: newRole }));
    } catch (error) {
      console.error("Error updating role:", error);
    }
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Gestion des utilisateurs</h1>
          <p className="text-muted-foreground mt-2">
            Gérer les rôles et permissions des utilisateurs
          </p>
        </div>

        {isDemoMode && (
          <Alert variant="default" className="bg-blue-50 border-blue-200 dark:bg-blue-900/20 dark:border-blue-800">
            <AlertCircle className="h-4 w-4 text-blue-600 dark:text-blue-400" />
            <AlertTitle className="text-blue-800 dark:text-blue-300">Mode Démo</AlertTitle>
            <AlertDescription className="text-blue-700 dark:text-blue-400">
              En mode démo, vous pouvez consulter les utilisateurs mais le changement de rôle est désactivé.
            </AlertDescription>
          </Alert>
        )}

        {/* Users Table */}
        <Card>
          <CardHeader>
            <CardTitle>Utilisateurs</CardTitle>
            <CardDescription>
              {users?.length || 0} utilisateur(s) enregistré(s)
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b">
                    <th className="text-left py-3 px-4 font-medium">Nom</th>
                    <th className="text-left py-3 px-4 font-medium">Email</th>
                    <th className="text-left py-3 px-4 font-medium">Rôle actuel</th>
                    <th className="text-left py-3 px-4 font-medium">Nouveau rôle</th>
                    <th className="text-left py-3 px-4 font-medium">Statut</th>
                    <th className="text-left py-3 px-4 font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {isLoading ? (
                    <tr>
                      <td colSpan={6} className="text-center py-6 text-muted-foreground">
                        Chargement...
                      </td>
                    </tr>
                  ) : users && users.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="text-center py-6 text-muted-foreground">
                        Aucun utilisateur trouvé
                      </td>
                    </tr>
                  ) : (
                    users?.map((user) => (
                      <tr key={user.id} className="border-b hover:bg-muted/50">
                        <td className="py-3 px-4 font-medium">{user.name || "-"}</td>
                        <td className="py-3 px-4">{user.email || "-"}</td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-1 rounded-full text-xs font-medium ${
                              user.role === "admin"
                                ? "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200"
                                : user.role === "doctor"
                                  ? "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"
                                  : user.role === "health_agent"
                                    ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
                                    : "bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200"
                            }`}
                          >
                            {user.role === "admin" && <Shield className="w-3 h-3 inline mr-1" />}
                            {user.role === "doctor" && <UserCheck className="w-3 h-3 inline mr-1" />}
                            {user.role === "health_agent" && <User className="w-3 h-3 inline mr-1" />}
                            {user.role}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <Select
                            value={selectedRole[user.id] || user.role}
                            onValueChange={(value) => setSelectedRole((prev) => ({ ...prev, [user.id]: value }))}
                            disabled={isDemoMode}
                          >
                            <SelectTrigger className="w-40">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="user">Utilisateur</SelectItem>
                              <SelectItem value="doctor">Médecin</SelectItem>
                              <SelectItem value="health_agent">Agent de santé</SelectItem>
                              <SelectItem value="admin">Administrateur</SelectItem>
                            </SelectContent>
                          </Select>
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-1 rounded-full text-xs font-medium ${
                              user.isActive
                                ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
                                : "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
                            }`}
                          >
                            {user.isActive ? "Actif" : "Inactif"}
                          </span>
                        </td>
                        <td className="py-3 px-4 flex gap-2">
                          <Button
                            size="sm"
                            onClick={() =>
                              handleRoleChange(user.id, selectedRole[user.id] || user.role)
                            }
                            disabled={updateRole.isPending || isDemoMode}
                          >
                            {isDemoMode ? "Désactivé" : "Appliquer"}
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
