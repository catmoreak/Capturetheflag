<template>
  <div class="cyberpunk-container">
    <!-- Three.js Background Canvas -->
    <canvas ref="threeCanvas" class="threejs-background"></canvas>
    
    <!-- Main Interface -->
    <div class="cyberpunk-interface">
      
      <!-- HUD Header -->
      <div class="hud-header">
        <div class="mission-status">
          <span class="status-indicator" :class="systemStatus.toLowerCase()">●</span>
          <span>MISSION STATUS: {{ systemStatus }}</span>
        </div>
        <div class="score-display">
          <span>SCORE: {{ totalScore }}</span>
          <span class="progress">{{ solvedCount }}/5</span>
        </div>
      </div>

      <!-- Challenge Window -->
      <div class="challenge-window" v-if="!allCompleted">
        <div class="window-header">
          <div class="window-title">
            <span class="window-icon">◉</span>
            <span>{{ currentChallenge.title }}</span>
          </div>
          <div class="difficulty-badge" :class="currentChallenge.difficulty">
            {{ currentChallenge.difficulty.toUpperCase() }}
          </div>
        </div>

        <div class="window-content">
          <!-- Challenge Info -->
          <div class="challenge-info">
            <div class="challenge-meta">
              <span class="challenge-id">ID: {{ String(currentChallenge.id).padStart(3, '0') }}</span>
              <span class="challenge-points">+{{ currentChallenge.points }} PTS</span>
            </div>
            <p class="challenge-description">{{ currentChallenge.description }}</p>
            
            <!-- Challenge specific content -->
            <div class="challenge-content">
              <!-- Caesar Cipher Data -->
              <div v-if="currentChallenge.id === 1" class="encrypted-data">
                <div class="data-label">INTERCEPTED_TRANSMISSION:</div>
                <div class="encrypted-text">PGS{FDHVDU_FLSKHU_VL_HDV}</div>
              </div>
              
              <!-- Web Exploit Login -->
              <div v-if="currentChallenge.id === 2" class="exploit-interface">
                <div class="login-form">
                  <input 
                    v-model="loginForm.username" 
                    placeholder="Username" 
                    class="exploit-input"
                  />
                  <input 
                    v-model="loginForm.password" 
                    placeholder="Password" 
                    type="password"
                    class="exploit-input"
                  />
                  <button @click="attemptLogin" class="exploit-button">LOGIN</button>
                </div>
                <div v-if="loginResult" class="login-result" :class="{ success: loginResult.includes('Successful') }">
                  {{ loginResult }}
                </div>
              </div>
              
              <!-- File Downloads -->
              <div v-if="currentChallenge.files" class="file-downloads">
                <div class="download-label">EVIDENCE_FILES:</div>
                <div class="file-list">
                  <div v-for="file in currentChallenge.files" :key="file.name" class="file-item">
                    <button @click="downloadFile(file.name)" class="download-btn">
                      ⬇ {{ file.name }}
                    </button>
                  </div>
                </div>
              </div>

              <!-- Network Analysis Info -->
              <div v-if="currentChallenge.id === 3" class="network-info">
                <div class="info-label">NETWORK_ANALYSIS_PROTOCOL:</div>
                <div class="analysis-steps">
                  <div class="step">1. Open Developer Tools (F12)</div>
                  <div class="step">2. Navigate to Network tab</div>
                  <div class="step">3. Refresh this page</div>
                  <div class="step">4. Examine HTTP response headers</div>
                  <div class="step">5. Look for X-CTF-Flag header</div>
                </div>
              </div>
            </div>
            
            <!-- Hint Section -->
            <div class="hint-section" v-if="showHint">
              <div class="hint-header">
                <span class="hint-icon">💡</span>
                <span>OPERATIONAL_HINT</span>
              </div>
              <p class="hint-text">{{ currentChallenge.hint }}</p>
              
              <!-- Tool Interface -->
              <div v-if="currentChallenge.id === 1 && showTool" class="tool-interface">
                <div class="tool-header">CIPHER_ANALYZER_v2.1</div>
                <div class="tool-output">{{ cipherResults }}</div>
              </div>
              
              <button v-if="currentChallenge.id === 1 && showHint && !showTool" 
                      @click="runCipherTool" 
                      class="tool-btn">
                RUN_CIPHER_ANALYZER
              </button>
            </div>
            
            <button v-if="!showHint" @click="requestHint" class="hint-btn">
              REQUEST_HINT
            </button>
          </div>

          <!-- Input Section -->
          <div class="input-section">
            <div class="flag-input-container">
              <input 
                v-model="flagInput" 
                @keyup.enter="submitFlag"
                type="text" 
                placeholder="Enter flag: CTF{...}"
                class="flag-input"
                :disabled="challengeCompleted"
              />
              <button @click="submitFlag" class="submit-btn" :disabled="challengeCompleted">
                {{ challengeCompleted ? 'COMPLETED' : 'SUBMIT' }}
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- Success/Completion Overlay -->
      <div class="completion-overlay" v-if="showCompletionScreen">
        <div class="completion-window">
          <div class="completion-header">
            <h2>{{ completionMessage }}</h2>
          </div>
          <div class="completion-stats">
            <div class="stat">
              <span class="label">Points Earned:</span>
              <span class="value">+{{ lastEarnedPoints }}</span>
            </div>
            <div class="stat">
              <span class="label">Total Score:</span>
              <span class="value">{{ totalScore }}</span>
            </div>
            <div class="stat">
              <span class="label">Progress:</span>
              <span class="value">{{ solvedCount }}/5</span>
            </div>
          </div>
          <button @click="proceedToNext" class="proceed-btn">
            {{ allCompleted ? 'MISSION COMPLETE' : 'CONTINUE' }}
          </button>
        </div>
      </div>
      
      <!-- Final Mission Complete Screen -->
      <div class="mission-complete" v-if="allCompleted && !showCompletionScreen">
        <div class="complete-header">
          <h1 class="glitch-text">MISSION ACCOMPLISHED</h1>
          <p>All challenges neutralized. Total score: {{ totalScore }}</p>
        </div>
        <div class="final-stats">
          <div class="stat-grid">
            <div class="stat-item">
              <div class="stat-value">{{ totalScore }}</div>
              <div class="stat-label">TOTAL POINTS</div>
            </div>
            <div class="stat-item">
              <div class="stat-value">5/5</div>
              <div class="stat-label">CHALLENGES</div>
            </div>
            <div class="stat-item">
              <div class="stat-value">100%</div>
              <div class="stat-label">SUCCESS RATE</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, reactive, onMounted, onUnmounted } from 'vue'
import * as THREE from 'three'

// Three.js references
const threeCanvas = ref<HTMLCanvasElement | null>(null)
let scene: THREE.Scene
let camera: THREE.PerspectiveCamera
let renderer: THREE.WebGLRenderer
let animationId: number
let particles: THREE.Points

// Challenge state
const currentChallengeIndex = ref(0)
const solvedChallenges = ref<Set<number>>(new Set())
const totalScore = ref(0)
const flagInput = ref('')
const showHint = ref(false)
const showTool = ref(false)
const challengeCompleted = ref(false)
const showCompletionScreen = ref(false)
const lastEarnedPoints = ref(0)
const completionMessage = ref('')

// Interactive elements
const loginForm = reactive({ username: '', password: '' })
const loginResult = ref('')
const cipherResults = ref('')

// Challenge definitions
const challenges = [
  {
    id: 0,
    title: 'BASIC_RECON.exe',
    difficulty: 'easy',
    points: 100,
    description: 'Extract hidden intelligence from web infrastructure. Deploy standard reconnaissance protocols.',
    hint: 'Use browser inspection tools. Search for HTML comments and hidden DOM elements. Ctrl+U or right-click inspection.',
    solution: 'CTF{view_source_is_basic_recon}'
  },
  {
    id: 1,
    title: 'CAESAR_DECRYPT.exe',
    difficulty: 'medium',
    points: 200,
    description: 'Decrypt intercepted classical cipher transmission. Ancient Roman encryption suspected.',
    hint: 'Deploy Caesar cipher analysis. Try alphabet shifting with variable offsets. Julius Caesar preferred method.',
    solution: 'CTF{caesar_cipher_is_easy}'
  },
  {
    id: 2,
    title: 'WEB_EXPLOIT.exe',
    difficulty: 'medium',
    points: 300,
    description: 'Bypass authentication system. Vulnerable web application detected. Exploit login mechanism.',
    hint: 'Deploy SQL injection payloads. Try: \' OR \'1\'=\'1, admin\'-- or similar bypass techniques.',
    solution: 'CTF{sql_injection_admin_bypass}'
  },
  {
    id: 3,
    title: 'NETWORK_ANALYSIS.exe',
    difficulty: 'medium',
    points: 400,
    description: 'Analyze network communications for hidden intelligence. Check HTTP headers for suspicious data.',
    hint: 'Open browser Network tab (F12 > Network), refresh the page and examine HTTP response headers for hidden flags.',
    solution: 'CTF{network_headers_exposed}'
  },
  {
    id: 4,
    title: 'REVERSE_ENGINEERING.exe',
    difficulty: 'expert',
    points: 500,
    description: 'Extract secrets from compiled binary. Reverse engineer target executable.',
    hint: 'Use strings analysis or disassembly tools. Look for embedded plaintext data.',
    files: [{ name: 'mystery_binary.exe' }],
    solution: 'CTF{binary_secrets_revealed}'
  }
]

// Computed properties
const currentChallenge = computed(() => challenges[currentChallengeIndex.value])
const solvedCount = computed(() => solvedChallenges.value.size)
const allCompleted = computed(() => solvedCount.value === 5)
const systemStatus = computed(() => {
  if (allCompleted.value) return 'COMPLETE'
  if (solvedCount.value === 0) return 'INITIALIZING'
  return 'IN_PROGRESS'
})

// Challenge functions
const submitFlag = () => {
  const challenge = currentChallenge.value
  
  if (flagInput.value.trim().toLowerCase() === challenge.solution.toLowerCase()) {
    totalScore.value += challenge.points
    solvedChallenges.value.add(currentChallengeIndex.value)
    lastEarnedPoints.value = challenge.points
    completionMessage.value = 'CHALLENGE NEUTRALIZED'
    showCompletionScreen.value = true
    challengeCompleted.value = true
    
    // Reset challenge-specific state
    showHint.value = false
    showTool.value = false
    flagInput.value = ''
    loginForm.username = ''
    loginForm.password = ''
    loginResult.value = ''
    cipherResults.value = ''
  } else {
    // Show error feedback
    alert('ACCESS DENIED - Invalid flag')
  }
}

const proceedToNext = () => {
  showCompletionScreen.value = false
  challengeCompleted.value = false
  
  if (currentChallengeIndex.value < challenges.length - 1) {
    currentChallengeIndex.value++
  }
}

const requestHint = () => {
  showHint.value = true
}

const runCipherTool = () => {
  showTool.value = true
  const encryptedText = "PGS{FDHVDU_FLSKHU_VL_HDV}"
  const results = []
  
  for (let i = 1; i <= 25; i++) {
    const decoded = caesarDecode(encryptedText, i)
    results.push(`SHIFT_${i.toString().padStart(2, '0')}: ${decoded}`)
    if (decoded.includes('CTF{')) {
      results.push(`>>> POTENTIAL_MATCH_DETECTED <<<`)
    }
  }
  
  cipherResults.value = results.join('\n')
}

const caesarDecode = (text: string, shift: number): string => {
  return text.replace(/[A-Z]/g, (char) => {
    const code = char.charCodeAt(0)
    const shifted = ((code - 65 - shift + 26) % 26) + 65
    return String.fromCharCode(shifted)
  })
}

const attemptLogin = () => {
  const { username, password } = loginForm
  const sqlInjectionPatterns = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--", 
    "' OR 'a'='a",
    "1' OR '1'='1",
    "' or 1=1#",
    "' or true--"
  ]
  
  const isInjection = sqlInjectionPatterns.some(pattern => 
    username.toLowerCase().includes(pattern.toLowerCase()) || 
    password.toLowerCase().includes(pattern.toLowerCase())
  )
  
  if (isInjection) {
    loginResult.value = `ACCESS GRANTED!\nWelcome Admin!\nFlag: CTF{sql_injection_admin_bypass}\nAuthentication bypassed via SQL injection!`
  } else {
    loginResult.value = 'ACCESS DENIED - Invalid credentials'
  }
}

const downloadFile = (filename: string) => {
  let mockData = ''
  let downloadName = filename
  
  if (filename === 'mystery_binary.exe') {
    downloadName = 'binary_analysis.txt'
    mockData = `Binary Analysis Report

File: mystery_binary.exe
Architecture: x86_64

STRINGS OUTPUT:
libc.so.6
Hello World  
Secret data found
CTF{binary_secrets_revealed}
Process complete

ANALYSIS:
Flag found as plaintext string in binary
No obfuscation detected
Use: strings mystery_binary.exe | grep CTF`
  }
  
  const blob = new Blob([mockData], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = downloadName
  a.click()
  URL.revokeObjectURL(url)
}

// Three.js initialization
const initThreeJS = () => {
  if (!threeCanvas.value) return
  
  // Scene setup
  scene = new THREE.Scene()
  camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000)
  renderer = new THREE.WebGLRenderer({ 
    canvas: threeCanvas.value, 
    alpha: true, 
    antialias: true,
    powerPreference: "high-performance"
  })
  renderer.setSize(window.innerWidth, window.innerHeight)
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
  renderer.setClearColor(0x000000, 0)
  
  // Optimized particle system
  const particleCount = 500
  const positions = new Float32Array(particleCount * 3)
  const colors = new Float32Array(particleCount * 3)
  const velocities = new Float32Array(particleCount * 3)
  
  for (let i = 0; i < particleCount; i++) {
    positions[i * 3] = (Math.random() - 0.5) * 80
    positions[i * 3 + 1] = (Math.random() - 0.5) * 80
    positions[i * 3 + 2] = (Math.random() - 0.5) * 80
    
    velocities[i * 3] = (Math.random() - 0.5) * 0.02
    velocities[i * 3 + 1] = (Math.random() - 0.5) * 0.02
    velocities[i * 3 + 2] = (Math.random() - 0.5) * 0.02
    
    // Elegant blue-purple color scheme
    const t = Math.random()
    colors[i * 3] = 0.4 + t * 0.3     // Red
    colors[i * 3 + 1] = 0.5 + t * 0.3 // Green  
    colors[i * 3 + 2] = 0.8 + t * 0.2 // Blue
  }
  
  const geometry = new THREE.BufferGeometry()
  geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3))
  geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3))
  
  const material = new THREE.PointsMaterial({
    size: 1.5,
    vertexColors: true,
    transparent: true,
    opacity: 0.4,
    blending: THREE.AdditiveBlending
  })
  
  particles = new THREE.Points(geometry, material)
  scene.add(particles)
  
  // Store velocities for animation
  particles.userData = { velocities }
  
  camera.position.z = 50
  
  animate()
}

const animate = () => {
  if (!renderer || !scene || !camera) return
  
  animationId = requestAnimationFrame(animate)
  
  // Smooth particle animation
  if (particles && particles.userData.velocities) {
    const positions = particles.geometry.attributes.position.array
    const velocities = particles.userData.velocities
    
    for (let i = 0; i < positions.length; i += 3) {
      positions[i] += velocities[i]
      positions[i + 1] += velocities[i + 1]
      positions[i + 2] += velocities[i + 2]
      
      // Boundary wrapping
      if (Math.abs(positions[i]) > 40) velocities[i] *= -1
      if (Math.abs(positions[i + 1]) > 40) velocities[i + 1] *= -1
      if (Math.abs(positions[i + 2]) > 40) velocities[i + 2] *= -1
    }
    
    particles.geometry.attributes.position.needsUpdate = true
    
    // Gentle rotation
    particles.rotation.x += 0.0005
    particles.rotation.y += 0.001
  }
  
  renderer.render(scene, camera)
}

const handleResize = () => {
  if (!camera || !renderer) return
  
  camera.aspect = window.innerWidth / window.innerHeight
  camera.updateProjectionMatrix()
  renderer.setSize(window.innerWidth, window.innerHeight)
}

// Lifecycle
onMounted(() => {
  // Add flag to DOM for basic recon challenge
  document.body.setAttribute('data-ctf-flag', 'CTF{view_source_is_basic_recon}')
  
  // Add hidden comment
  const comment = document.createComment(' Hidden flag: CTF{view_source_is_basic_recon} ')
  document.head.appendChild(comment)
  
  // Add network challenge header - simulate via meta tag that shows in network requests
  const metaFlag = document.createElement('meta')
  metaFlag.setAttribute('name', 'X-CTF-Flag')
  metaFlag.setAttribute('content', 'CTF{network_headers_exposed}')
  document.head.appendChild(metaFlag)
  
  // Also add to body for easier discovery
  document.body.setAttribute('data-network-flag', 'Check Network tab for X-CTF-Flag header: CTF{network_headers_exposed}')
  
  initThreeJS()
  window.addEventListener('resize', handleResize)
})

onUnmounted(() => {
  if (animationId) {
    cancelAnimationFrame(animationId)
  }
  window.removeEventListener('resize', handleResize)
})
</script>

<style scoped>
/* Global Styles */
.cyberpunk-container {
  min-height: 100vh;
  background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 50%, #16213e 100%);
  color: #e0e6ed;
  font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
  position: relative;
  overflow: hidden;
}

.threejs-background {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  z-index: 0;
  pointer-events: none;
  opacity: 0.7;
}

.cyberpunk-interface {
  position: relative;
  z-index: 1;
  min-height: 100vh;
  padding: 2rem;
  display: flex;
  flex-direction: column;
}

/* HUD Header */
.hud-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1.5rem 2rem;
  background: rgba(255, 255, 255, 0.02);
  border: 1px solid rgba(99, 102, 241, 0.3);
  border-radius: 12px;
  margin-bottom: 2rem;
  backdrop-filter: blur(20px);
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
}

.mission-status {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  font-weight: 600;
  font-size: 1rem;
}

.status-indicator {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  animation: pulse 2s infinite;
}

.status-indicator.initializing {
  background: #f59e0b;
  box-shadow: 0 0 10px rgba(245, 158, 11, 0.5);
}

.status-indicator.in_progress {
  background: #3b82f6;
  box-shadow: 0 0 10px rgba(59, 130, 246, 0.5);
}

.status-indicator.complete {
  background: #10b981;
  box-shadow: 0 0 10px rgba(16, 185, 129, 0.5);
}

.score-display {
  display: flex;
  gap: 2rem;
  font-weight: 600;
  font-size: 1rem;
}

.progress {
  color: #3b82f6;
}

/* Challenge Window */
.challenge-window {
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(99, 102, 241, 0.2);
  border-radius: 16px;
  max-width: 900px;
  margin: 0 auto;
  backdrop-filter: blur(20px);
  box-shadow: 
    0 20px 60px rgba(0, 0, 0, 0.4),
    0 8px 32px rgba(99, 102, 241, 0.1);
  transition: all 0.3s ease;
}

.challenge-window:hover {
  box-shadow: 
    0 24px 80px rgba(0, 0, 0, 0.5),
    0 12px 40px rgba(99, 102, 241, 0.15);
}

.window-header {
  background: rgba(99, 102, 241, 0.05);
  padding: 1.5rem 2rem;
  border-bottom: 1px solid rgba(99, 102, 241, 0.1);
  border-radius: 16px 16px 0 0;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.window-title {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  font-weight: 600;
  font-size: 1.3rem;
}

.window-icon {
  color: #6366f1;
  font-size: 1.1rem;
}

.difficulty-badge {
  padding: 0.5rem 1rem;
  border-radius: 20px;
  font-size: 0.8rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.difficulty-badge.easy {
  background: rgba(16, 185, 129, 0.1);
  color: #10b981;
  border: 1px solid rgba(16, 185, 129, 0.3);
}

.difficulty-badge.medium {
  background: rgba(245, 158, 11, 0.1);
  color: #f59e0b;
  border: 1px solid rgba(245, 158, 11, 0.3);
}

.difficulty-badge.hard {
  background: rgba(239, 68, 68, 0.1);
  color: #ef4444;
  border: 1px solid rgba(239, 68, 68, 0.3);
}

.difficulty-badge.expert {
  background: rgba(139, 69, 19, 0.1);
  color: #8b4513;
  border: 1px solid rgba(139, 69, 19, 0.3);
}

.window-content {
  padding: 2rem;
}

/* Challenge Content */
.challenge-info {
  margin-bottom: 2rem;
}

.challenge-meta {
  display: flex;
  gap: 2rem;
  margin-bottom: 1rem;
  font-size: 0.9rem;
}

.challenge-id {
  color: #666;
}

.challenge-points {
  color: #ffff00;
  font-weight: bold;
}

.challenge-description {
  font-size: 1.1rem;
  line-height: 1.7;
  margin-bottom: 2rem;
  color: #9ca3af;
  font-weight: 400;
}

.challenge-content {
  margin: 2rem 0;
}

.encrypted-data {
  background: rgba(99, 102, 241, 0.05);
  border: 1px solid rgba(99, 102, 241, 0.2);
  border-radius: 8px;
  padding: 1.5rem;
}

.data-label {
  color: #6366f1;
  font-weight: 600;
  margin-bottom: 0.75rem;
  font-size: 0.9rem;
  text-transform: uppercase;
  letter-spacing: 1px;
}

.encrypted-text {
  background: rgba(0, 0, 0, 0.3);
  padding: 1.5rem;
  font-family: 'JetBrains Mono', 'Courier New', monospace;
  letter-spacing: 1px;
  text-align: center;
  border: 1px solid rgba(99, 102, 241, 0.3);
  border-radius: 6px;
  color: #e0e6ed;
  font-size: 1.1rem;
}

/* Exploit Interface */
.exploit-interface {
  background: rgba(255, 255, 255, 0.02);
  border: 1px solid rgba(99, 102, 241, 0.2);
  border-radius: 8px;
  padding: 2rem;
}

.login-form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  max-width: 350px;
}

.exploit-input {
  padding: 1rem;
  background: rgba(255, 255, 255, 0.03);
  border: 1px solid rgba(156, 163, 175, 0.3);
  border-radius: 6px;
  color: #e0e6ed;
  font-family: 'Inter', sans-serif;
  transition: all 0.3s ease;
}

.exploit-input:focus {
  border-color: #6366f1;
  outline: none;
  box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
  background: rgba(99, 102, 241, 0.05);
}

.exploit-button {
  padding: 1rem;
  background: linear-gradient(135deg, #ef4444, #dc2626);
  border: none;
  border-radius: 6px;
  color: white;
  cursor: pointer;
  font-family: 'Inter', sans-serif;
  font-weight: 600;
  transition: all 0.3s ease;
  box-shadow: 0 4px 12px rgba(239, 68, 68, 0.3);
}

.exploit-button:hover {
  background: linear-gradient(135deg, #dc2626, #b91c1c);
  box-shadow: 0 6px 20px rgba(239, 68, 68, 0.4);
  transform: translateY(-1px);
}

.login-result {
  margin-top: 1.5rem;
  padding: 1rem;
  background: rgba(239, 68, 68, 0.1);
  border: 1px solid rgba(239, 68, 68, 0.3);
  border-radius: 6px;
  color: #ef4444;
  white-space: pre-line;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.9rem;
}

.login-result.success {
  background: rgba(16, 185, 129, 0.1);
  border-color: rgba(16, 185, 129, 0.3);
  color: #10b981;
}

/* File Downloads */
.file-downloads {
  margin: 2rem 0;
}

.download-label {
  color: #3b82f6;
  font-weight: 600;
  margin-bottom: 1rem;
  font-size: 0.9rem;
  text-transform: uppercase;
  letter-spacing: 1px;
}

.file-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.download-btn {
  padding: 1rem 1.5rem;
  background: rgba(59, 130, 246, 0.1);
  border: 1px solid rgba(59, 130, 246, 0.3);
  border-radius: 6px;
  color: #3b82f6;
  cursor: pointer;
  text-align: left;
  font-family: 'Inter', sans-serif;
  font-weight: 500;
  transition: all 0.3s ease;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.download-btn:hover {
  background: rgba(59, 130, 246, 0.15);
  border-color: rgba(59, 130, 246, 0.4);
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(59, 130, 246, 0.2);
}

/* Network Analysis */
.network-info {
  margin: 2rem 0;
  background: rgba(99, 102, 241, 0.05);
  border: 1px solid rgba(99, 102, 241, 0.2);
  border-radius: 8px;
  padding: 2rem;
}

.info-label {
  color: #6366f1;
  font-weight: 600;
  margin-bottom: 1rem;
  font-size: 0.9rem;
  text-transform: uppercase;
  letter-spacing: 1px;
}

.analysis-steps {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.step {
  padding: 0.75rem;
  background: rgba(0, 0, 0, 0.2);
  border-left: 3px solid #6366f1;
  border-radius: 4px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.9rem;
  color: #e0e6ed;
}

/* Hint Section */
.hint-section {
  background: rgba(245, 158, 11, 0.05);
  border: 1px solid rgba(245, 158, 11, 0.2);
  border-radius: 8px;
  padding: 2rem;
  margin: 2rem 0;
}

.hint-header {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 1rem;
  color: #f59e0b;
  font-weight: 600;
}

.hint-text {
  color: #9ca3af;
  line-height: 1.7;
  margin-bottom: 1.5rem;
}

.tool-interface {
  margin-top: 2rem;
  background: rgba(0, 0, 0, 0.2);
  border-radius: 6px;
  padding: 1.5rem;
}

.tool-header {
  color: #6366f1;
  font-weight: 600;
  margin-bottom: 1rem;
  padding-bottom: 0.5rem;
  border-bottom: 1px solid rgba(99, 102, 241, 0.2);
  font-size: 0.9rem;
  text-transform: uppercase;
  letter-spacing: 1px;
}

.tool-output {
  background: rgba(0, 0, 0, 0.4);
  padding: 1.5rem;
  font-family: 'JetBrains Mono', 'Courier New', monospace;
  font-size: 0.85rem;
  white-space: pre-line;
  max-height: 300px;
  overflow-y: auto;
  border: 1px solid rgba(99, 102, 241, 0.2);
  border-radius: 4px;
  color: #e0e6ed;
}

.hint-btn, .tool-btn {
  background: rgba(245, 158, 11, 0.1);
  color: #f59e0b;
  border: 1px solid rgba(245, 158, 11, 0.3);
  border-radius: 6px;
  padding: 0.75rem 1.5rem;
  cursor: pointer;
  font-family: 'Inter', sans-serif;
  font-weight: 600;
  transition: all 0.3s ease;
  font-size: 0.9rem;
}

.hint-btn:hover, .tool-btn:hover {
  background: rgba(245, 158, 11, 0.15);
  border-color: rgba(245, 158, 11, 0.4);
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(245, 158, 11, 0.2);
}

/* Input Section */
.input-section {
  border-top: 1px solid rgba(99, 102, 241, 0.1);
  padding-top: 2rem;
}

.flag-input-container {
  display: flex;
  gap: 1rem;
}

.flag-input {
  flex: 1;
  padding: 1rem 1.5rem;
  background: rgba(255, 255, 255, 0.02);
  border: 2px solid rgba(99, 102, 241, 0.3);
  border-radius: 8px;
  color: #e0e6ed;
  font-family: 'JetBrains Mono', 'Courier New', monospace;
  font-size: 1rem;
  outline: none;
  transition: all 0.3s ease;
}

.flag-input:focus {
  border-color: #6366f1;
  box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
  background: rgba(99, 102, 241, 0.05);
}

.flag-input::placeholder {
  color: #6b7280;
}

.submit-btn {
  padding: 1rem 2rem;
  background: linear-gradient(135deg, #6366f1, #8b5cf6);
  border: none;
  border-radius: 8px;
  color: white;
  cursor: pointer;
  font-family: 'Inter', sans-serif;
  font-weight: 600;
  font-size: 1rem;
  transition: all 0.3s ease;
  box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3);
}

.submit-btn:hover:not(:disabled) {
  background: linear-gradient(135deg, #5b5ef6, #7c3aed);
  box-shadow: 0 6px 20px rgba(99, 102, 241, 0.4);
  transform: translateY(-1px);
}

.submit-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
  transform: none;
}

/* Completion Overlay */
.completion-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0, 0, 0, 0.8);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  backdrop-filter: blur(20px);
}

.completion-window {
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(16, 185, 129, 0.3);
  border-radius: 16px;
  padding: 3rem;
  text-align: center;
  max-width: 500px;
  box-shadow: 
    0 20px 60px rgba(0, 0, 0, 0.4),
    0 8px 32px rgba(16, 185, 129, 0.1);
  animation: fadeInUp 0.5s ease-out;
}

.completion-header h2 {
  color: #10b981;
  font-size: 2rem;
  margin-bottom: 2rem;
  font-weight: 700;
}

.completion-stats {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
  margin-bottom: 2rem;
}

.stat {
  display: flex;
  justify-content: space-between;
  font-size: 1.1rem;
  padding: 0.5rem 0;
  border-bottom: 1px solid rgba(156, 163, 175, 0.1);
  font-weight: 500;
}

.label {
  color: #9ca3af;
}

.value {
  color: #10b981;
  font-weight: 600;
}

.proceed-btn {
  background: linear-gradient(135deg, #10b981, #059669);
  border: none;
  border-radius: 8px;
  color: white;
  padding: 1rem 2rem;
  cursor: pointer;
  font-family: 'Inter', sans-serif;
  font-weight: 600;
  font-size: 1.1rem;
  transition: all 0.3s ease;
  box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);
}

.proceed-btn:hover {
  background: linear-gradient(135deg, #059669, #047857);
  box-shadow: 0 6px 20px rgba(16, 185, 129, 0.4);
  transform: translateY(-1px);
}

/* Mission Complete */
.mission-complete {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  text-align: center;
}

.complete-header {
  margin-bottom: 4rem;
}

.glitch-text {
  font-size: 4rem;
  color: #10b981;
  margin-bottom: 2rem;
  font-weight: 700;
  background: linear-gradient(135deg, #10b981, #059669);
  background-clip: text;
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  animation: glow 2s ease-in-out infinite alternate;
}

@keyframes glow {
  from {
    filter: drop-shadow(0 0 20px rgba(16, 185, 129, 0.5));
  }
  to {
    filter: drop-shadow(0 0 30px rgba(16, 185, 129, 0.7));
  }
}

.final-stats {
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(99, 102, 241, 0.2);
  border-radius: 16px;
  padding: 2rem;
}

.stat-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 2rem;
}

.stat-item {
  text-align: center;
  padding: 1.5rem;
  background: rgba(255, 255, 255, 0.02);
  border-radius: 8px;
  border: 1px solid rgba(156, 163, 175, 0.1);
}

.stat-value {
  font-size: 2.5rem;
  color: #6366f1;
  font-weight: 700;
  margin-bottom: 0.5rem;
}

.stat-label {
  color: #9ca3af;
  font-size: 0.9rem;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 1px;
}

/* Animations */
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.7; }
}

@keyframes fadeInUp {
  from {
    opacity: 0;
    transform: translateY(20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.challenge-window {
  animation: fadeInUp 0.5s ease-out;
}

/* Responsive */
@media (max-width: 768px) {
  .cyberpunk-interface {
    padding: 1rem;
  }
  
  .hud-header {
    flex-direction: column;
    gap: 1rem;
    padding: 1rem;
  }
  
  .flag-input-container {
    flex-direction: column;
  }
  
  .stat-grid {
    grid-template-columns: 1fr;
    gap: 1rem;
  }
  
  .glitch-text {
    font-size: 2.5rem;
  }
}
</style>