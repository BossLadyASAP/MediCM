import { useState } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useAuth } from "@/_core/hooks/useAuth";
import {
  Building2,
  User,
  Palette,
  Bell,
  AlertCircle,
} from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

export default function ProfessionalSettings() {
  const { isDemoMode } = useAuth();
  const [healthCenter, setHealthCenter] = useState({
    name: "Centre de Santé Principal",
    region: "Centre",
    address: "Yaoundé",
    phone: "+237 6 XX XXX XXX",
    email: "contact@centre.cm",
  });

  const [doctor, setDoctor] = useState({
    name: "Dr. Jean Dupont",
    specialty: "Médecin Généraliste",
    license: "ML-2024-001",
    phone: "+237 6 XX XXX XXX",
  });

  const [branding, setBranding] = useState({
    appName: "MedicM Pro",
    primaryColor: "#0066CC",
    secondaryColor: "#00AA44",
    logoUrl: "",
  });

  const handleSaveHealthCenter = () => {
    if (isDemoMode) return;
    console.log("Saving health center:", healthCenter);
    alert("Paramètres du centre de santé sauvegardés !");
  };

  const handleSaveDoctor = () => {
    if (isDemoMode) return;
    console.log("Saving doctor info:", doctor);
    alert("Informations du médecin sauvegardées !");
  };

  const handleSaveBranding = () => {
    if (isDemoMode) return;
    console.log("Saving branding:", branding);
    alert("Paramètres de marque sauvegardés !");
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold text-slate-900 dark:text-white">
            Paramètres Professionnels
          </h1>
          <p className="text-slate-600 dark:text-slate-400 mt-2">
            Gérez les paramètres de votre centre de santé et de votre profil
            professionnel
          </p>
        </div>

        {isDemoMode && (
          <Alert variant="default" className="bg-blue-50 border-blue-200 dark:bg-blue-900/20 dark:border-blue-800">
            <AlertCircle className="h-4 w-4 text-blue-600 dark:text-blue-400" />
            <AlertTitle className="text-blue-800 dark:text-blue-300">Mode Démo</AlertTitle>
            <AlertDescription className="text-blue-700 dark:text-blue-400">
              En mode démo, vous pouvez explorer les paramètres mais la modification est désactivée.
            </AlertDescription>
          </Alert>
        )}

        <Tabs defaultValue="health-center" className="w-full">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="health-center" className="flex items-center gap-2">
              <Building2 className="w-4 h-4" />
              <span className="hidden sm:inline">Centre</span>
            </TabsTrigger>
            <TabsTrigger value="doctor" className="flex items-center gap-2">
              <User className="w-4 h-4" />
              <span className="hidden sm:inline">Profil</span>
            </TabsTrigger>
            <TabsTrigger value="branding" className="flex items-center gap-2">
              <Palette className="w-4 h-4" />
              <span className="hidden sm:inline">Marque</span>
            </TabsTrigger>
            <TabsTrigger value="notifications" className="flex items-center gap-2">
              <Bell className="w-4 h-4" />
              <span className="hidden sm:inline">Alertes</span>
            </TabsTrigger>
          </TabsList>

          {/* Health Center Settings */}
          <TabsContent value="health-center" className="space-y-6">
            <Card className="p-6">
              <h2 className="text-2xl font-bold text-slate-900 dark:text-white mb-6">
                Paramètres du Centre de Santé
              </h2>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                    Nom du Centre
                  </label>
                  <Input
                    value={healthCenter.name}
                    onChange={(e) =>
                      setHealthCenter({ ...healthCenter, name: e.target.value })
                    }
                    placeholder="Nom du centre de santé"
                    className="w-full"
                    disabled={isDemoMode}
                  />
                </div>
                <div className="grid md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                      Région
                    </label>
                    <Input
                      value={healthCenter.region}
                      onChange={(e) =>
                        setHealthCenter({
                          ...healthCenter,
                          region: e.target.value,
                        })
                      }
                      placeholder="Région"
                      disabled={isDemoMode}
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                      Adresse
                    </label>
                    <Input
                      value={healthCenter.address}
                      onChange={(e) =>
                        setHealthCenter({
                          ...healthCenter,
                          address: e.target.value,
                        })
                      }
                      placeholder="Adresse"
                      disabled={isDemoMode}
                    />
                  </div>
                </div>
                <div className="grid md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                      Téléphone
                    </label>
                    <Input
                      value={healthCenter.phone}
                      onChange={(e) =>
                        setHealthCenter({
                          ...healthCenter,
                          phone: e.target.value,
                        })
                      }
                      placeholder="Téléphone"
                      disabled={isDemoMode}
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                      Email
                    </label>
                    <Input
                      value={healthCenter.email}
                      onChange={(e) =>
                        setHealthCenter({
                          ...healthCenter,
                          email: e.target.value,
                        })
                      }
                      placeholder="Email"
                      disabled={isDemoMode}
                    />
                  </div>
                </div>
                <Button
                  onClick={handleSaveHealthCenter}
                  className="bg-blue-600 hover:bg-blue-700 w-full"
                  disabled={isDemoMode}
                >
                  {isDemoMode ? "Modification désactivée" : "Sauvegarder les Paramètres"}
                </Button>
              </div>
            </Card>
          </TabsContent>

          {/* Doctor Profile Settings */}
          <TabsContent value="doctor" className="space-y-6">
            <Card className="p-6">
              <h2 className="text-2xl font-bold text-slate-900 dark:text-white mb-6">
                Profil Professionnel
              </h2>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                    Nom Complet
                  </label>
                  <Input
                    value={doctor.name}
                    onChange={(e) =>
                      setDoctor({ ...doctor, name: e.target.value })
                    }
                    placeholder="Nom du médecin"
                    disabled={isDemoMode}
                  />
                </div>
                <div className="grid md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                      Spécialité
                    </label>
                    <Input
                      value={doctor.specialty}
                      onChange={(e) =>
                        setDoctor({ ...doctor, specialty: e.target.value })
                      }
                      placeholder="Spécialité"
                      disabled={isDemoMode}
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                      Numéro de Licence
                    </label>
                    <Input
                      value={doctor.license}
                      onChange={(e) =>
                        setDoctor({ ...doctor, license: e.target.value })
                      }
                      placeholder="Numéro de licence"
                      disabled={isDemoMode}
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                    Téléphone
                    </label>
                  <Input
                    value={doctor.phone}
                    onChange={(e) =>
                      setDoctor({ ...doctor, phone: e.target.value })
                    }
                    placeholder="Téléphone"
                    disabled={isDemoMode}
                  />
                </div>
                <Button
                  onClick={handleSaveDoctor}
                  className="bg-blue-600 hover:bg-blue-700 w-full"
                  disabled={isDemoMode}
                >
                  {isDemoMode ? "Modification désactivée" : "Sauvegarder le Profil"}
                </Button>
              </div>
            </Card>
          </TabsContent>

          {/* Branding Settings */}
          <TabsContent value="branding" className="space-y-6">
            <Card className="p-6">
              <h2 className="text-2xl font-bold text-slate-900 dark:text-white mb-6">
                Paramètres de Marque
              </h2>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                    Nom de l'Application
                  </label>
                  <Input
                    value={branding.appName}
                    onChange={(e) =>
                      setBranding({ ...branding, appName: e.target.value })
                    }
                    placeholder="Nom de l'application"
                    disabled={isDemoMode}
                  />
                </div>
                <div className="grid md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                      Couleur Primaire
                    </label>
                    <div className="flex items-center gap-2">
                      <input
                        type="color"
                        value={branding.primaryColor}
                        onChange={(e) =>
                          setBranding({
                            ...branding,
                            primaryColor: e.target.value,
                          })
                        }
                        className="w-12 h-10 rounded cursor-pointer"
                        disabled={isDemoMode}
                      />
                      <Input
                        value={branding.primaryColor}
                        onChange={(e) =>
                          setBranding({
                            ...branding,
                            primaryColor: e.target.value,
                          })
                        }
                        placeholder="#0066CC"
                        disabled={isDemoMode}
                      />
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                      Couleur Secondaire
                    </label>
                    <div className="flex items-center gap-2">
                      <input
                        type="color"
                        value={branding.secondaryColor}
                        onChange={(e) =>
                          setBranding({
                            ...branding,
                            secondaryColor: e.target.value,
                          })
                        }
                        className="w-12 h-10 rounded cursor-pointer"
                        disabled={isDemoMode}
                      />
                      <Input
                        value={branding.secondaryColor}
                        onChange={(e) =>
                          setBranding({
                            ...branding,
                            secondaryColor: e.target.value,
                          })
                        }
                        placeholder="#00AA44"
                        disabled={isDemoMode}
                      />
                    </div>
                  </div>
                </div>
                <Button
                  onClick={handleSaveBranding}
                  className="bg-blue-600 hover:bg-blue-700 w-full"
                  disabled={isDemoMode}
                >
                  {isDemoMode ? "Modification désactivée" : "Sauvegarder les Paramètres"}
                </Button>
              </div>
            </Card>
          </TabsContent>

          {/* Notifications Settings */}
          <TabsContent value="notifications" className="space-y-6">
            <Card className="p-6">
              <h2 className="text-2xl font-bold text-slate-900 dark:text-white mb-6">
                Paramètres des Alertes
              </h2>
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 border rounded-lg">
                  <div>
                    <p className="font-medium">Alertes de Cas Sévères</p>
                    <p className="text-sm text-slate-500">Recevoir une notification pour chaque nouveau cas sévère</p>
                  </div>
                  <input type="checkbox" defaultChecked disabled={isDemoMode} className="w-5 h-5" />
                </div>
                <div className="flex items-center justify-between p-4 border rounded-lg">
                  <div>
                    <p className="font-medium">Rapports Hebdomadaires</p>
                    <p className="text-sm text-slate-500">Recevoir un résumé hebdomadaire des statistiques</p>
                  </div>
                  <input type="checkbox" defaultChecked disabled={isDemoMode} className="w-5 h-5" />
                </div>
                <div className="flex items-center justify-between p-4 border rounded-lg">
                  <div>
                    <p className="font-medium">Alertes de Seuil</p>
                    <p className="text-sm text-slate-500">Notifier si le nombre de patients dépasse un certain seuil</p>
                  </div>
                  <input type="checkbox" disabled={isDemoMode} className="w-5 h-5" />
                </div>
                <Button
                  className="bg-blue-600 hover:bg-blue-700 w-full"
                  disabled={isDemoMode}
                >
                  {isDemoMode ? "Modification désactivée" : "Sauvegarder les Préférences"}
                </Button>
              </div>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </DashboardLayout>
  );
}
