import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': process.env.VITE_API_PROXY_TARGET || 'http://localhost:3000',
      // Dev-server mirror of the training-only FauxPay proxy in web/nginx.conf.
      // Not part of any production build — see that file for the deployed
      // topology, where the browser reaches the real processor directly.
      '/fauxpay': {
        target: process.env.VITE_FAUXPAY_PROXY_TARGET || 'http://localhost:4000',
        rewrite: (path) => path.replace(/^\/fauxpay/, ''),
      },
    },
  },
});
