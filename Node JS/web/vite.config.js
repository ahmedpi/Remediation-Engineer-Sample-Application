import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import basicSsl from '@vitejs/plugin-basic-ssl';

export default defineConfig({
  plugins: [react(), basicSsl()],
  server: {
    port: 5173,
    https: true,
    proxy: {
      '/api': process.env.VITE_API_PROXY_TARGET || 'http://localhost:3000',
      '/fauxpay': {
        target: process.env.VITE_FAUXPAY_PROXY_TARGET || 'http://localhost:4000',
        rewrite: (path) => path.replace(/^\/fauxpay/, ''),
      },
    },
  },
});
