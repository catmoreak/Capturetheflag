
export default defineNuxtConfig({
  compatibilityDate: '2025-07-15',
  devtools: { enabled: true },
  

  ssr: true,
  
 
  build: {
    transpile: ['three']
  },
  
  
  vite: {
    define: {
      global: 'globalThis'
    },
    optimizeDeps: {
      include: ['three']
    }
  },
  

  nitro: {
    esbuild: {
      options: {
        target: 'es2020'
      }
    }
  }
})
