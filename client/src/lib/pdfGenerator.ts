/**
 * PDF Generator for Medical Records
 * Generates professional medical record PDFs with health center and doctor information
 */

export interface PatientData {
  patientName: string;
  age: number;
  sex: string;
  email: string;
  phone: string;
  address: string;
  region: string;
  primaryPathology: string;
  severity: string;
  temperature: number;
  patientSatisfaction: number;
  createdAt: Date;
  lastVisit: Date;
}

export interface HealthCenterData {
  name: string;
  region: string;
  address: string;
  phone: string;
  email: string;
}

export interface DoctorData {
  name: string;
  specialty: string;
  license: string;
}

/**
 * Generate a professional medical record PDF
 */
export function generatePatientRecordPDF(
  patient: PatientData,
  healthCenter: HealthCenterData,
  doctor: DoctorData
): Blob {
  const htmlContent = `
    <!DOCTYPE html>
    <html lang="fr">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Fiche Patient - ${patient.patientName}</title>
      <style>
        * {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
        }
        
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          color: #333;
          line-height: 1.6;
          background: white;
        }
        
        .container {
          max-width: 210mm;
          height: 297mm;
          margin: 0 auto;
          padding: 20mm;
          background: white;
        }
        
        .header {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          border-bottom: 3px solid #0066CC;
          padding-bottom: 15px;
          margin-bottom: 20px;
        }
        
        .header-left h1 {
          font-size: 24px;
          color: #0066CC;
          margin-bottom: 5px;
        }
        
        .header-left p {
          font-size: 12px;
          color: #666;
        }
        
        .header-right {
          text-align: right;
          font-size: 11px;
        }
        
        .header-right p {
          margin: 3px 0;
          color: #666;
        }
        
        .section {
          margin-bottom: 20px;
        }
        
        .section-title {
          background: #0066CC;
          color: white;
          padding: 8px 12px;
          font-size: 14px;
          font-weight: bold;
          margin-bottom: 10px;
          border-radius: 3px;
        }
        
        .section-content {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 15px;
        }
        
        .field {
          font-size: 12px;
        }
        
        .field-label {
          font-weight: bold;
          color: #0066CC;
          margin-bottom: 3px;
        }
        
        .field-value {
          color: #333;
          padding: 5px;
          background: #f5f5f5;
          border-left: 3px solid #00AA44;
          padding-left: 8px;
        }
        
        .full-width {
          grid-column: 1 / -1;
        }
        
        .severity-badge {
          display: inline-block;
          padding: 3px 8px;
          border-radius: 3px;
          font-size: 11px;
          font-weight: bold;
        }
        
        .severity-light {
          background: #d4edda;
          color: #155724;
        }
        
        .severity-moderate {
          background: #fff3cd;
          color: #856404;
        }
        
        .severity-severe {
          background: #f8d7da;
          color: #721c24;
        }
        
        .signature-section {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 30px;
          margin-top: 40px;
          padding-top: 20px;
          border-top: 1px solid #ddd;
        }
        
        .signature-block {
          font-size: 11px;
        }
        
        .signature-line {
          border-top: 1px solid #333;
          margin-top: 30px;
          padding-top: 5px;
        }
        
        .footer {
          text-align: center;
          font-size: 10px;
          color: #999;
          margin-top: 30px;
          padding-top: 10px;
          border-top: 1px solid #ddd;
        }
        
        @media print {
          body {
            margin: 0;
            padding: 0;
          }
          .container {
            margin: 0;
            padding: 20mm;
            height: auto;
          }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <!-- Header -->
        <div class="header">
          <div class="header-left">
            <h1>MedicM Pro</h1>
            <p>Système de Gestion Médicale Avancé</p>
          </div>
          <div class="header-right">
            <p><strong>${healthCenter.name}</strong></p>
            <p>${healthCenter.address}</p>
            <p>Région: ${healthCenter.region}</p>
            <p>Tél: ${healthCenter.phone}</p>
            <p>Email: ${healthCenter.email}</p>
          </div>
        </div>
        
        <!-- Patient Information -->
        <div class="section">
          <div class="section-title">INFORMATIONS PERSONNELLES</div>
          <div class="section-content">
            <div class="field">
              <div class="field-label">Nom Complet</div>
              <div class="field-value">${patient.patientName}</div>
            </div>
            <div class="field">
              <div class="field-label">Âge</div>
              <div class="field-value">${patient.age} ans</div>
            </div>
            <div class="field">
              <div class="field-label">Sexe</div>
              <div class="field-value">${patient.sex}</div>
            </div>
            <div class="field">
              <div class="field-label">Région</div>
              <div class="field-value">${patient.region}</div>
            </div>
            <div class="field full-width">
              <div class="field-label">Email</div>
              <div class="field-value">${patient.email}</div>
            </div>
            <div class="field full-width">
              <div class="field-label">Téléphone</div>
              <div class="field-value">${patient.phone}</div>
            </div>
            <div class="field full-width">
              <div class="field-label">Adresse</div>
              <div class="field-value">${patient.address}</div>
            </div>
          </div>
        </div>
        
        <!-- Medical Information -->
        <div class="section">
          <div class="section-title">INFORMATIONS MÉDICALES</div>
          <div class="section-content">
            <div class="field">
              <div class="field-label">Pathologie Principale</div>
              <div class="field-value">${patient.primaryPathology}</div>
            </div>
            <div class="field">
              <div class="field-label">Sévérité</div>
              <div class="field-value">
                <span class="severity-badge ${
                  patient.severity === "Légère"
                    ? "severity-light"
                    : patient.severity === "Modérée"
                      ? "severity-moderate"
                      : "severity-severe"
                }">
                  ${patient.severity}
                </span>
              </div>
            </div>
            <div class="field">
              <div class="field-label">Température</div>
              <div class="field-value">${patient.temperature}°C</div>
            </div>
            <div class="field">
              <div class="field-label">Satisfaction Patient</div>
              <div class="field-value">${patient.patientSatisfaction}/5 ⭐</div>
            </div>
          </div>
        </div>
        
        <!-- History -->
        <div class="section">
          <div class="section-title">HISTORIQUE</div>
          <div class="section-content">
            <div class="field">
              <div class="field-label">Date d'Enregistrement</div>
              <div class="field-value">${patient.createdAt.toLocaleDateString("fr-FR")}</div>
            </div>
            <div class="field">
              <div class="field-label">Dernière Visite</div>
              <div class="field-value">${patient.lastVisit.toLocaleDateString("fr-FR")}</div>
            </div>
          </div>
        </div>
        
        <!-- Observations -->
        <div class="section">
          <div class="section-title">OBSERVATIONS CLINIQUES</div>
          <div style="height: 60px; border: 1px dashed #ccc; padding: 8px; font-size: 12px; color: #999;">
            [Espace pour les observations du médecin]
          </div>
        </div>
        
        <!-- Signatures -->
        <div class="signature-section">
          <div class="signature-block">
            <strong>Médecin Responsable</strong>
            <p style="margin-top: 5px; font-size: 11px;">
              ${doctor.name}<br>
              ${doctor.specialty}<br>
              Licence: ${doctor.license}
            </p>
            <div class="signature-line">Signature</div>
          </div>
          <div class="signature-block">
            <strong>Date</strong>
            <div class="signature-line">${new Date().toLocaleDateString("fr-FR")}</div>
          </div>
        </div>
        
        <!-- Footer -->
        <div class="footer">
          <p>Document généré par MedicM Pro - Système de Gestion Médicale Avancé</p>
          <p>Confidentiel - À usage professionnel uniquement</p>
        </div>
      </div>
    </body>
    </html>
  `;

  return new Blob([htmlContent], { type: "text/html;charset=utf-8" });
}

/**
 * Download a file as blob
 */
export function downloadFile(blob: Blob, filename: string) {
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(url);
  document.body.removeChild(a);
}

/**
 * Generate CSV export
 */
export function generatePatientCSV(
  patient: PatientData,
  healthCenter: HealthCenterData,
  doctor: DoctorData
): Blob {
  const csv = `FICHE PATIENT - EXPORT CSV
Centre de Santé,${healthCenter.name}
Région,${healthCenter.region}
Adresse,${healthCenter.address}
Téléphone,${healthCenter.phone}
Email,${healthCenter.email}

Médecin,${doctor.name}
Spécialité,${doctor.specialty}
Licence,${doctor.license}

Nom Patient,${patient.patientName}
Âge,${patient.age}
Sexe,${patient.sex}
Email,${patient.email}
Téléphone,${patient.phone}
Adresse,${patient.address}
Région,${patient.region}
Pathologie,${patient.primaryPathology}
Sévérité,${patient.severity}
Température,${patient.temperature}
Satisfaction,${patient.patientSatisfaction}
Date Enregistrement,${patient.createdAt.toLocaleDateString("fr-FR")}
Dernière Visite,${patient.lastVisit.toLocaleDateString("fr-FR")}
`;

  return new Blob([csv], { type: "text/csv;charset=utf-8" });
}
