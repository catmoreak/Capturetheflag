// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  compatibilityDate: '2025-07-15',
  devtools: { enabled: true },
  
  // Handle Three.js properly
  ssr: true,
  
  // Build configuration for Three.js
  build: {
    transpile: ['three']
  },
  
  // Vite configuration for client-side dependencies
  vite: {
    define: {
      global: 'globalThis'
    },
    optimizeDeps: {
      include: ['three']
    }
  },
  
  // Nitro configuration
  nitro: {
    esbuild: {
      options: {
        target: 'es2020'
      }
    }
  }
})
