import { useState } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Download, ArrowLeft, Phone, Mail, MapPin, Calendar } from "lucide-react";
import {
  generatePatientRecordPDF,
  generatePatientCSV,
  downloadFile,
  type PatientData,
  type HealthCenterData,
  type DoctorData,
} from "@/lib/pdfGenerator";

export default function PatientDetail() {
  const [patient] = useState<PatientData>({
    patientName: "Jean Dupont",
    age: 45,
    sex: "Masculin",
    region: "Centre",
    primaryPathology: "Hypertension",
    severity: "Modérée",
    temperature: 37.2,
    patientSatisfaction: 4.5,
    email: "jean.dupont@email.com",
    phone: "+237 6 XX XXX XXX",
    address: "Yaoundé, Centre",
    createdAt: new Date("2026-04-20"),
    lastVisit: new Date("2026-04-25"),
  });

  const healthCenter: HealthCenterData = {
    name: "Centre de Santé Principal",
    region: patient.region,
    address: "Yaoundé, Centre",
    phone: "+237 6 XX XXX XXX",
    email: "contact@centre.cm",
  };

  const doctor: DoctorData = {
    name: "Dr. Jean Dupont",
    specialty: "Médecin Généraliste",
    license: "ML-2024-001",
  };

  const handleDownloadPDF = () => {
    const blob = generatePatientRecordPDF(patient, healthCenter, doctor);
    downloadFile(
      blob,
      `fiche-patient-${patient.patientName.replace(/ /g, "-")}.html`
    );
  };

  const handleDownloadCSV = () => {
    const blob = generatePatientCSV(patient, healthCenter, doctor);
    downloadFile(
      blob,
      `fiche-patient-${patient.patientName.replace(/ /g, "-")}.csv`
    );
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "Légère":
        return "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200";
      case "Modérée":
        return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200";
      case "Sévère":
        return "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200";
      default:
        return "bg-gray-100 text-gray-800";
    }
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Button variant="outline" size="icon">
              <ArrowLeft className="w-4 h-4" />
            </Button>
            <div>
              <h1 className="text-3xl font-bold text-slate-900 dark:text-white">
                {patient.patientName}
              </h1>
              <p className="text-slate-600 dark:text-slate-400">
                Fiche Patient Professionnelle
              </p>
            </div>
          </div>
          <div className="flex gap-2">
            <Button
              onClick={handleDownloadPDF}
              className="bg-blue-600 hover:bg-blue-700"
            >
              <Download className="w-4 h-4 mr-2" />
              Télécharger PDF
            </Button>
            <Button
              onClick={handleDownloadCSV}
              variant="outline"
            >
              <Download className="w-4 h-4 mr-2" />
              Télécharger CSV
            </Button>
          </div>
        </div>

        {/* Main Content */}
        <div className="grid md:grid-cols-3 gap-6">
          {/* Left Column - Personal Info */}
          <div className="md:col-span-2 space-y-6">
            <Card className="p-6">
              <h2 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">
                Informations Personnelles
              </h2>
              <div className="grid md:grid-cols-2 gap-6">
                <div>
                  <label className="text-sm font-medium text-slate-600 dark:text-slate-400">
                    Âge
                  </label>
                  <p className="text-lg text-slate-900 dark:text-white">
                    {patient.age} ans
                  </p>
                </div>
                <div>
                  <label className="text-sm font-medium text-slate-600 dark:text-slate-400">
                    Sexe
                  </label>
                  <p className="text-lg text-slate-900 dark:text-white">
                    {patient.sex}
                  </p>
                </div>
                <div>
                  <label className="text-sm font-medium text-slate-600 dark:text-slate-400">
                    Région
                  </label>
                  <p className="text-lg text-slate-900 dark:text-white">
                    {patient.region}
                  </p>
                </div>
                <div>
                  <label className="text-sm font-medium text-slate-600 dark:text-slate-400">
                    Température
                  </label>
                  <p className="text-lg text-slate-900 dark:text-white">
                    {patient.temperature}°C
                  </p>
                </div>
              </div>
            </Card>

            <Card className="p-6">
              <h2 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">
                Informations Médicales
              </h2>
              <div className="space-y-4">
                <div>
                  <label className="text-sm font-medium text-slate-600 dark:text-slate-400">
                    Pathologie Principale
                  </label>
                  <p className="text-lg text-slate-900 dark:text-white">
                    {patient.primaryPathology}
                  </p>
                </div>
                <div>
                  <label className="text-sm font-medium text-slate-600 dark:text-slate-400">
                    Sévérité
                  </label>
                  <Badge className={getSeverityColor(patient.severity)}>
                    {patient.severity}
                  </Badge>
                </div>
                <div>
                  <label className="text-sm font-medium text-slate-600 dark:text-slate-400">
                    Satisfaction du Patient
                  </label>
                  <p className="text-lg text-slate-900 dark:text-white">
                    {patient.patientSatisfaction}/5 ⭐
                  </p>
                </div>
              </div>
            </Card>

            <Card className="p-6">
              <h2 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">
                Médecin Responsable
              </h2>
              <div className="space-y-3">
                <div>
                  <label className="text-sm font-medium text-slate-600 dark:text-slate-400">
                    Nom
                  </label>
                  <p className="text-slate-900 dark:text-white">{doctor.name}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-slate-600 dark:text-slate-400">
                    Spécialité
                  </label>
                  <p className="text-slate-900 dark:text-white">{doctor.specialty}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-slate-600 dark:text-slate-400">
                    Numéro de Licence
                  </label>
                  <p className="text-slate-900 dark:text-white">{doctor.license}</p>
                </div>
              </div>
            </Card>
          </div>

          {/* Right Column - Contact Info */}
          <div className="space-y-6">
            <Card className="p-6">
              <h2 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">
                Contact
              </h2>
              <div className="space-y-4">
                <div className="flex items-center gap-3">
                  <Mail className="w-5 h-5 text-blue-600" />
                  <div>
                    <p className="text-sm text-slate-600 dark:text-slate-400">
                      Email
                    </p>
                    <p className="text-slate-900 dark:text-white">
                      {patient.email}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <Phone className="w-5 h-5 text-blue-600" />
                  <div>
                    <p className="text-sm text-slate-600 dark:text-slate-400">
                      Téléphone
                    </p>
                    <p className="text-slate-900 dark:text-white">
                      {patient.phone}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <MapPin className="w-5 h-5 text-blue-600" />
                  <div>
                    <p className="text-sm text-slate-600 dark:text-slate-400">
                      Adresse
                    </p>
                    <p className="text-slate-900 dark:text-white">
                      {patient.address}
                    </p>
                  </div>
                </div>
              </div>
            </Card>

            <Card className="p-6">
              <h2 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">
                Centre de Santé
              </h2>
              <div className="space-y-3">
                <div>
                  <label className="text-sm font-medium text-slate-600 dark:text-slate-400">
                    Nom
                  </label>
                  <p className="text-slate-900 dark:text-white">{healthCenter.name}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-slate-600 dark:text-slate-400">
                    Région
                  </label>
                  <p className="text-slate-900 dark:text-white">{healthCenter.region}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-slate-600 dark:text-slate-400">
                    Adresse
                  </label>
                  <p className="text-slate-900 dark:text-white">{healthCenter.address}</p>
                </div>
              </div>
            </Card>

            <Card className="p-6">
              <h2 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">
                Historique
              </h2>
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <Calendar className="w-4 h-4 text-slate-600 dark:text-slate-400" />
                  <div>
                    <p className="text-sm text-slate-600 dark:text-slate-400">
                      Enregistrement
                    </p>
                    <p className="text-slate-900 dark:text-white">
                      {patient.createdAt.toLocaleDateString("fr-FR")}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Calendar className="w-4 h-4 text-slate-600 dark:text-slate-400" />
                  <div>
                    <p className="text-sm text-slate-600 dark:text-slate-400">
                      Dernière Visite
                    </p>
                    <p className="text-slate-900 dark:text-white">
                      {patient.lastVisit.toLocaleDateString("fr-FR")}
                    </p>
                  </div>
                </div>
              </div>
            </Card>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
