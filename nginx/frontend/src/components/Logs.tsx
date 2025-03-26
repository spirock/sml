import React, { useEffect, useState } from 'react';

const Logs: React.FC = () => {
  const [logs, setLogs] = useState<any[]>([]); // Puedes tipar mejor según el contenido de tus logs

  useEffect(() => {
    fetch("http://fastapi:8000/logs")
      .then((res) => res.json())
      .then((data) => setLogs(data));
  }, []);

  return (
    <div className="p-4 shadow rounded-xl">
      <h2 className="text-xl font-bold mb-4">📄 Logs de Suricata</h2>
      <div className="text-sm font-mono bg-gray-100 p-2 rounded max-h-[300px] overflow-auto">
        {logs.map((log, idx) => (
          <pre key={idx}>{JSON.stringify(log, null, 2)}</pre>
        ))}
      </div>
    </div>
  );
};

export default Logs;
