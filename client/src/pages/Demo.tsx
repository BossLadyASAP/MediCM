import { useEffect } from "react";
import { useLocation } from "wouter";

export default function Demo() {
  const [, setLocation] = useLocation();

  useEffect(() => {
    localStorage.setItem("demoMode", "true");
    // Redirect to dashboard after setting demo mode
    setLocation("/");
  }, [setLocation]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-950 dark:to-slate-900">
      <div className="text-center">
        <h2 className="text-xl font-semibold text-slate-900 dark:text-white">Chargement du mode démo...</h2>
        <p className="text-slate-600 dark:text-slate-400 mt-2">Veuillez patienter quelques instants.</p>
      </div>
    </div>
  );
}
