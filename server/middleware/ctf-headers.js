export default defineEventHandler((event) => {
 
  setHeader(event, 'X-CTF-Flag', 'CTF{network_headers_exposed}')
  setHeader(event, 'X-CTF-Challenge', 'Network-Analysis')
  setHeader(event, 'X-Server-Info', 'CTF-Platform-v1.0')
})