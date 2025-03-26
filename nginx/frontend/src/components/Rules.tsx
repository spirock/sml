import React, { useEffect, useState } from 'react';

const Rules: React.FC = () => {
  const [rules, setRules] = useState<string[]>([]);

  useEffect(() => {
    fetch("http://fastapi:8000/rules")
      .then((res) => res.json())
      .then((data) => setRules(data.rules || []));
  }, []);

  return (
    <div className="p-4 shadow rounded-xl">
      <h2 className="text-xl font-bold mb-4">📜 Reglas Suricata</h2>
      <ul className="text-sm font-mono bg-gray-100 p-2 rounded max-h-[300px] overflow-auto">
        {rules.map((rule, idx) => (
          <li key={idx}>{rule}</li>
        ))}
      </ul>
    </div>
  );
};

export default Rules;
