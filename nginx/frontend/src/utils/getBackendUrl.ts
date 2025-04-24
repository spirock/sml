// src/utils/getBackendUrl.ts
export const getBackendUrl = async (): Promise<string> => {
    try {
      const res = await fetch("http://localhost:8000/host-ip");
      const data = await res.json();
      const ip = data.ip;
  
      // Devuelve la URL base completa del backend
      return `http://${ip}:8000`;
    } catch (error) {
      console.error("❌ Error obteniendo la IP del backend:", error);
      return "http://localhost:8000"; // fallback en caso de error
    }
  };
  