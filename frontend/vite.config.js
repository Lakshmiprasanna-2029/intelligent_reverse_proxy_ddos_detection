import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],

  server: {
    host: "127.0.0.1",

    proxy: {
      "/health": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },

      "/system": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },

      "/dashboard": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },

      "/proxy": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },

      "/predict": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },

      "/risk": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },
    },
  },
});