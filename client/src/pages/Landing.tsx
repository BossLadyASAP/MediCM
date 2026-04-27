import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { useAuth } from "@/_core/hooks/useAuth";
import { getLoginUrl } from "@/const";
import { useLocation } from "wouter";
import {
  BarChart3,
  Users,
  TrendingUp,
  Shield,
  Zap,
  Heart,
} from "lucide-react";

export default function Landing() {
  const { isAuthenticated } = useAuth();
  const [, setLocation] = useLocation();

  if (isAuthenticated) {
    setLocation("/");
    return null;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-950 dark:to-slate-900">
      {/* Navigation */}
      <nav className="fixed top-0 w-full bg-white/80 dark:bg-slate-900/80 backdrop-blur-md border-b border-slate-200 dark:border-slate-800 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex justify-between items-center">
          <div className="flex items-center gap-2">
            <Heart className="w-8 h-8 text-blue-600" />
            <span className="text-2xl font-bold text-slate-900 dark:text-white">
              MedicM Pro
            </span>
          </div>
          <div className="flex gap-4">
            <Button
              variant="outline"
              onClick={() => (window.location.href = getLoginUrl())}
            >
              Se connecter
            </Button>
            <Button
              onClick={() => (window.location.href = getLoginUrl())}
              className="bg-blue-600 hover:bg-blue-700"
            >
              S'inscrire
            </Button>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="pt-32 pb-20 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto text-center">
          <h1 className="text-5xl sm:text-6xl font-bold text-slate-900 dark:text-white mb-6 leading-tight">
            Gestion Médicale
            <span className="text-blue-600"> Intelligente</span>
          </h1>
          <p className="text-xl text-slate-600 dark:text-slate-300 mb-8 max-w-2xl mx-auto">
            Plateforme complète de gestion des dossiers patients, analyses
            épidémiologiques et insights IA pour les centres de santé.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center mb-16">
            <Button
              size="lg"
              onClick={() => setLocation("/demo")}
              className="bg-green-600 hover:bg-green-700 text-white"
            >
              Voir la Démo
            </Button>
            <Button
              size="lg"
              variant="outline"
              onClick={() => (window.location.href = getLoginUrl())}
            >
              Créer un Compte
            </Button>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 px-4 sm:px-6 lg:px-8 bg-white dark:bg-slate-800">
        <div className="max-w-7xl mx-auto">
          <h2 className="text-4xl font-bold text-center text-slate-900 dark:text-white mb-16">
            Fonctionnalités Principales
          </h2>
          <div className="grid md:grid-cols-3 gap-8">
            {[
              {
                icon: BarChart3,
                title: "Tableau de Bord Avancé",
                description:
                  "KPIs en temps réel, graphiques interactifs et statistiques détaillées",
              },
              {
                icon: Users,
                title: "Gestion Patients",
                description:
                  "Dossiers médicaux complets, historique et recherche avancée",
              },
              {
                icon: TrendingUp,
                title: "Analyses IA",
                description:
                  "Insights épidémiologiques générés automatiquement par IA",
              },
              {
                icon: Shield,
                title: "Sécurité Complète",
                description:
                  "Authentification sécurisée, audit log et contrôle d'accès",
              },
              {
                icon: Zap,
                title: "Exports Professionnels",
                description:
                  "Téléchargement de rapports en PDF et CSV avec design professionnel",
              },
              {
                icon: Heart,
                title: "Multi-Rôles",
                description:
                  "Admin, médecins et agents de santé avec permissions granulaires",
              },
            ].map((feature, idx) => (
              <Card key={idx} className="p-6 hover:shadow-lg transition-shadow">
                <feature.icon className="w-12 h-12 text-blue-600 mb-4" />
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-2">
                  {feature.title}
                </h3>
                <p className="text-slate-600 dark:text-slate-300">
                  {feature.description}
                </p>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 px-4 sm:px-6 lg:px-8">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-4xl font-bold text-slate-900 dark:text-white mb-6">
            Prêt à Transformer Votre Gestion Médicale ?
          </h2>
          <p className="text-xl text-slate-600 dark:text-slate-300 mb-8">
            Rejoignez les centres de santé qui font confiance à MedicM Pro pour
            une gestion efficace et professionnelle.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Button
              size="lg"
              onClick={() => setLocation("/demo")}
              className="bg-green-600 hover:bg-green-700 text-white"
            >
              Explorer la Démo Gratuite
            </Button>
            <Button
              size="lg"
              variant="outline"
              onClick={() => (window.location.href = getLoginUrl())}
            >
              S'inscrire Maintenant
            </Button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-slate-200 dark:border-slate-800 py-8 px-4 sm:px-6 lg:px-8 bg-slate-50 dark:bg-slate-900">
        <div className="max-w-7xl mx-auto text-center text-slate-600 dark:text-slate-400">
          <p>&copy; 2026 MedicM Pro. Tous droits réservés.</p>
        </div>
      </footer>
    </div>
  );
}
