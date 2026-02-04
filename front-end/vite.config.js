import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(({ mode }) => {
  // Load env file based on `mode` in the current working directory.
  const env = loadEnv(mode, process.cwd(), '')

  // 3. PRIORITY CHECK:
  // If VITE_BACKEND_URL is set (from Docker), use it.
  // Otherwise, fallback to localhost (for local dev).
  const target = process.env.VITE_BACKEND_URL || 'http://127.0.0.1:5000';
  
  // Debug print to see what is happening in the logs
  console.log("🔌 VITE PROXY TARGET:", target); 

  return {
    plugins: [react()],
    server: {
      host: true,
      port: 5173,
      proxy: {
        '/api': {
          target: target,
          changeOrigin: true,
          secure: false,
        }
      }
    }
  }
})