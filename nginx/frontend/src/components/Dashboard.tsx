import React, { useEffect, useState } from 'react';

interface Stats {
  total_events: number;
  anomalies_detected: number;
  anomaly_percentage: number;
  top_anomalous_ips: { _id: string; count: number }[];
}

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<Stats | null>(null);
  const backendUrl = process.env.REACT_APP_BACKEND_URL ;

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const res = await fetch(`${backendUrl}/stats`);
        const data = await res.json();
        setStats(data);
      } catch (error) {
        console.error("❌ Error al cargar estadísticas:", error);
      }
    };

    fetchStats();
  }, [backendUrl]);

  if (!stats) return <p>🔄 Cargando estadísticas...</p>;

  return (
    <div className="p-4 shadow rounded-xl">
      <h2 className="text-xl font-bold mb-4">📊 Estadísticas del Sistema</h2>
      <p>Total de eventos: {stats.total_events}</p>
      <p>Anomalías detectadas: {stats.anomalies_detected}</p>
      <p>Porcentaje de anomalías: {stats.anomaly_percentage.toFixed(2)}%</p>

      <h3 className="mt-4 font-semibold">Top IPs con anomalías</h3>
      <ul className="list-disc list-inside">
        {stats.top_anomalous_ips.map((ip, index) => (
          <li key={index}>{ip._id} ({ip.count} eventos)</li>
        ))}
      </ul>
    </div>
  );
};

export default Dashboard;
