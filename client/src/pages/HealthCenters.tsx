import DashboardLayout from "@/components/DashboardLayout";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useState } from "react";
import { Plus, Edit, Trash2, MapPin, Phone, Mail } from "lucide-react";

export default function HealthCenters() {
  const { data: healthCenters, isLoading } = trpc.healthCenter.list.useQuery();
  const [showForm, setShowForm] = useState(false);
  const [formData, setFormData] = useState({
    name: "",
    region: "",
    address: "",
    phone: "",
    email: "",
  });

  const createCenter = trpc.healthCenter.create.useMutation();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await createCenter.mutateAsync(formData);
      setFormData({ name: "", region: "", address: "", phone: "", email: "" });
      setShowForm(false);
    } catch (error) {
      console.error("Error creating health center:", error);
    }
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Centres de santé</h1>
            <p className="text-muted-foreground mt-2">
              Gestion des centres de santé et des structures médicales
            </p>
          </div>
          <Button onClick={() => setShowForm(!showForm)} className="gap-2">
            <Plus className="w-4 h-4" />
            Nouveau centre
          </Button>
        </div>

        {/* Add Form */}
        {showForm && (
          <Card>
            <CardHeader>
              <CardTitle>Ajouter un centre de santé</CardTitle>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="text-sm font-medium">Nom</label>
                    <Input
                      placeholder="Nom du centre"
                      value={formData.name}
                      onChange={(e) =>
                        setFormData({ ...formData, name: e.target.value })
                      }
                      required
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium">Région</label>
                    <Input
                      placeholder="Région"
                      value={formData.region}
                      onChange={(e) =>
                        setFormData({ ...formData, region: e.target.value })
                      }
                      required
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium">Adresse</label>
                    <Input
                      placeholder="Adresse"
                      value={formData.address}
                      onChange={(e) =>
                        setFormData({ ...formData, address: e.target.value })
                      }
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium">Téléphone</label>
                    <Input
                      placeholder="Téléphone"
                      value={formData.phone}
                      onChange={(e) =>
                        setFormData({ ...formData, phone: e.target.value })
                      }
                    />
                  </div>
                  <div className="md:col-span-2">
                    <label className="text-sm font-medium">Email</label>
                    <Input
                      type="email"
                      placeholder="Email"
                      value={formData.email}
                      onChange={(e) =>
                        setFormData({ ...formData, email: e.target.value })
                      }
                    />
                  </div>
                </div>
                <div className="flex gap-2">
                  <Button type="submit" disabled={createCenter.isPending}>
                    {createCenter.isPending ? "Création..." : "Créer"}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setShowForm(false)}
                  >
                    Annuler
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>
        )}

        {/* Health Centers Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {isLoading ? (
            <p className="text-muted-foreground">Chargement...</p>
          ) : healthCenters && healthCenters.length > 0 ? (
            healthCenters.map((center) => (
              <Card key={center.id} className="hover:shadow-lg transition-shadow">
                <CardHeader className="pb-3">
                  <CardTitle className="text-lg">{center.name}</CardTitle>
                  <CardDescription>{center.region}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  {center.address && (
                    <div className="flex items-start gap-2 text-sm">
                      <MapPin className="w-4 h-4 text-muted-foreground mt-0.5 flex-shrink-0" />
                      <span>{center.address}</span>
                    </div>
                  )}
                  {center.phone && (
                    <div className="flex items-center gap-2 text-sm">
                      <Phone className="w-4 h-4 text-muted-foreground" />
                      <span>{center.phone}</span>
                    </div>
                  )}
                  {center.email && (
                    <div className="flex items-center gap-2 text-sm">
                      <Mail className="w-4 h-4 text-muted-foreground" />
                      <span>{center.email}</span>
                    </div>
                  )}
                  <div className="flex gap-2 pt-3 border-t">
                    <Button variant="outline" size="sm" className="flex-1">
                      <Edit className="w-4 h-4 mr-1" />
                      Modifier
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      className="flex-1 text-destructive"
                    >
                      <Trash2 className="w-4 h-4 mr-1" />
                      Supprimer
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))
          ) : (
            <p className="text-muted-foreground">Aucun centre de santé</p>
          )}
        </div>
      </div>
    </DashboardLayout>
  );
}
