<template>
  <div class="cyberpunk-container">
    <!-- Loading Screen -->
    <div v-if="isLoading" class="loading-screen">
      <div class="loading-content">
        <div class="loading-spinner"></div>
        <div class="loading-text">INITIALIZING SYSTEMS...</div>
      </div>
    </div>
    
   
    <canvas ref="threeCanvas" class="threejs-background" :style="{ display: isLoading ? 'none' : 'block' }"></canvas>
    

    <div v-if="showNameModal" class="modal-overlay">
      <div class="name-modal">
        <div class="modal-header">
          <h2 class="modal-title">◉ OPERATOR IDENTIFICATION</h2>
          <p class="modal-subtitle">Enter your callsign to begin the mission</p>
        </div>
        <div class="modal-content">
          <div class="input-group">
            <label for="username">CALLSIGN:</label>
            <input 
              id="username"
              v-model="userName" 
              @keyup.enter="registerUser"
              type="text" 
              placeholder="Enter your name..."
              class="name-input"
              maxlength="20"
              required
            />
          </div>
          <button @click="registerUser" :disabled="!userName.trim()" class="register-btn">
            <span v-if="!isRegistering">INITIALIZE SYSTEM</span>
            <span v-else>CONNECTING...</span>
          </button>
        </div>
      </div>
    </div>
    
    
    <div class="cyberpunk-interface" v-show="!isLoading && !showNameModal">
      
     
      <div class="hud-header">
        <div class="mission-status">
          <span class="status-indicator" :class="systemStatus.toLowerCase()">●</span>
          <span>MISSION STATUS: {{ systemStatus }}</span>
        </div>
        <div class="score-display">
          <span>SCORE: {{ totalScore }}</span>
          <span class="progress">{{ solvedCount }}/5</span>
          <NuxtLink to="/leaderboard" class="leaderboard-link">🏆 LEADERBOARD</NuxtLink>
        </div>
      </div>

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
  
          <div class="challenge-info">
            <div class="challenge-meta">
              <span class="challenge-id">ID: {{ String(currentChallenge.id).padStart(3, '0') }}</span>
              <span class="challenge-points">+{{ currentChallenge.points }} PTS</span>
            </div>
            <p class="challenge-description">{{ currentChallenge.description }}</p>
            
          
            <div class="challenge-content">
             
              <div v-if="currentChallenge.id === 1" class="encrypted-data">
                <div class="data-label">INTERCEPTED_TRANSMISSION:</div>
                                <p>Intercept encrypted transmission:</p>
                <div class="encrypted-text">PGS{PNRFNE_PVCURE_VF_RNFL}</div>
              </div>
              
             
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
              
              <!-- Steganography Image -->
              <div v-if="currentChallenge.id === 3" class="stego-interface">
                <div class="data-label">INTERCEPTED_IMAGE:</div>
                <div class="image-container">
                  <img 
                    src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==" 
                    alt="Suspicious Image" 
                    class="stego-image"
                    title="CTF{hidden_pixels_tell_secrets}"
                  />
                  <p class="image-hint">Right-click and inspect this image for hidden data...</p>
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

              <!-- JavaScript Obfuscation Challenge -->
              <div v-if="currentChallenge.id === 4" class="js-obfuscation-interface">
                <div class="data-label">OBFUSCATED_CODE:</div>
                <div class="code-container">
                  <pre class="obfuscated-code">
function _0x1234(){
  var _0x5678=['Q1RGe2phdmFzY3JpcHRfc2VjcmV0c19kZWNvZGVkfQ=='];
  return _0x5678;
}
var secret = atob(_0x1234()[0]);
console.log('Hidden flag:', secret);
                  </pre>
                  <p class="code-hint">Open your browser console and analyze this JavaScript code...</p>
                </div>
              </div>

              <!-- Forensics Challenge -->
              <div v-if="currentChallenge.id === 5" class="forensics-interface">
                <div class="data-label">EVIDENCE_COLLECTED:</div>
                <div class="forensics-container">
                  <div class="evidence-item" data-flag="CTF{forensics_investigation_complete}">
                    <div class="evidence-header">📋 INCIDENT_REPORT_2025.txt</div>
                    <div class="evidence-content">
                      <p>Agent compromised at 14:32 UTC. Extraction protocol initiated.</p>
                      <p>Recovery status: <span style="color: var(--primary-color);">SUCCESSFUL</span></p>
                      <p class="hidden-data"><!-- Investigation complete: CTF{forensics_investigation_complete} --></p>
                    </div>
                  </div>
                  <p class="forensics-hint">Examine the evidence carefully. Some data may be hidden from plain sight...</p>
                </div>
              </div>
            </div>
            
           
            <div class="hint-section" v-if="showHint">
              <div class="hint-header">
                <span class="hint-icon">💡</span>
                <span>OPERATIONAL_HINT</span>
              </div>
              <p class="hint-text">{{ currentChallenge.hint }}</p>
              
           
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
const threeCanvas = ref<HTMLCanvasElement | null>(null)
let scene: THREE.Scene | null = null
let camera: THREE.PerspectiveCamera | null = null
let renderer: THREE.WebGLRenderer | null = null
let animationId: number | null = null
let particles: THREE.Points | null = null
const isLoading = ref(true)
const threeJsLoaded = ref(false)
const showNameModal = ref(false)
const currentUser = ref<any>(null)
const userName = ref('')
const challengeStartTime = ref<number>(0)
const isRegistering = ref(false)
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
const loginForm = reactive({ username: '', password: '' })
const loginResult = ref('')
const cipherResults = ref('')
interface Challenge {
  id: number
  title: string
  difficulty: string
  points: number
  description: string
  hint: string
  solution: string
  files?: { name: string }[]
}
const challenges: Challenge[] = [
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
    title: 'STEGANOGRAPHY.exe',
    difficulty: 'medium',
    points: 400,
    description: 'Extract hidden intelligence from digital image. Visual data contains concealed transmission.',
    hint: 'Analyze the image data. Look for hidden text in image properties, metadata, or pixel manipulation. Right-click > Inspect element on images.',
    solution: 'CTF{hidden_pixels_tell_secrets}'
  },
  {
    id: 4,
    title: 'JS_OBFUSCATION.exe',
    difficulty: 'medium',
    points: 500,
    description: 'Decode obfuscated JavaScript to reveal hidden credentials. Client-side security bypass detected.',
    hint: 'Open browser console (F12 > Console) and analyze the obfuscated JavaScript function. Look for encoded strings or hidden variables.',
    solution: 'CTF{javascript_secrets_decoded}'
  },
  {
    id: 5,
    title: 'FORENSICS_ANALYSIS.exe',
    difficulty: 'hard',
    points: 600,
    description: 'Examine digital evidence for hidden data. Investigate suspicious network communications and extract intelligence.',
    hint: 'Check the page source for hidden comments or inspect network requests. Look for data hidden in HTML attributes or CSS properties.',
    solution: 'CTF{forensics_investigation_complete}'
  }
]

const currentChallenge = computed((): Challenge => {
  const index = Math.max(0, Math.min(currentChallengeIndex.value, challenges.length - 1))
  return challenges[index]!
})
const solvedCount = computed(() => solvedChallenges.value.size)
const allCompleted = computed(() => solvedCount.value === 6)
const systemStatus = computed(() => {
  if (allCompleted.value) return 'COMPLETE'
  if (solvedCount.value === 0) return 'INITIALIZING'
  return 'IN_PROGRESS'
})
const registerUser = async () => {
  if (!userName.value.trim()) return
  
  isRegistering.value = true
  
  try {
    const response = await $fetch('/api/users/register', {
      method: 'POST',
      body: {
        name: userName.value.trim()
      }
    }) as any
    
    if (response.success) {
      currentUser.value = response.user
      
      localStorage.setItem('ctf-user', JSON.stringify(response.user))
      showNameModal.value = false
      
      challengeStartTime.value = Date.now()
      
      await restoreUserProgress(response.user.id)

    }
  } catch (error) {
    console.error('Registration failed:', error)
    alert('Registration failed. Please try again.')
  } finally {
    isRegistering.value = false
  }
}

const restoreUserProgress = async (userId: string) => {
  try {
    console.log('🔍 Starting progress restoration for user:', userId)
    const response = await $fetch(`/api/users/progress?userId=${userId}`) as any
    console.log('📡 API response:', response)
    
    if (response.success && response.completions.length > 0) {
      console.log('✅ Found completions:', response.completions.length)
      
     
      const completedChallengeIds = new Set<number>()
      let restoredScore = 0
      
      response.completions.forEach((completion: any) => {
        console.log('📝 Processing completion:', completion)
        completedChallengeIds.add(completion.challengeId)
        restoredScore += completion.points
      })
      
      console.log('🎯 Completed challenge IDs:', Array.from(completedChallengeIds))
      console.log('💰 Total restored score:', restoredScore)
      
      
      solvedChallenges.value = completedChallengeIds
      totalScore.value = restoredScore
      
      console.log('🧩 Total challenges available:', challenges.length)
      console.log('🏆 Challenges completed:', completedChallengeIds.size)
      
    
      let nextChallengeIndex = 0
      
      for (let i = 0; i < challenges.length; i++) {
        const challenge = challenges[i]
        console.log(`🔍 Checking challenge ${i}: ${challenge?.title} (ID: ${challenge?.id})`)
        
        if (challenge && !completedChallengeIds.has(challenge.id)) {
          console.log(`🎯 Found first uncompleted challenge at index ${i}`)
          nextChallengeIndex = i
          break
        } else {
          console.log(`✅ Challenge ${i} is already completed, continuing...`)
          
          nextChallengeIndex = i + 1
        }
      }
      
      
      if (nextChallengeIndex >= challenges.length) {
        console.log('🏁 All challenges completed, staying at last challenge')
        nextChallengeIndex = challenges.length - 1
      }
      
      console.log('📊 Setting current challenge index to:', nextChallengeIndex)
      currentChallengeIndex.value = nextChallengeIndex
      
      
      const currentChallenge = challenges[nextChallengeIndex]
      if (currentChallenge && completedChallengeIds.has(currentChallenge.id)) {
        console.log('✅ Current challenge is already completed')
        challengeCompleted.value = true
      } else {
        console.log('🔄 Current challenge is not completed yet')
        challengeCompleted.value = false
      }
      
      console.log(`📋 RESTORATION SUMMARY:`)
      console.log(`   - Challenges completed: ${completedChallengeIds.size}`)
      console.log(`   - Points restored: ${restoredScore}`)
      console.log(`   - Current challenge index: ${nextChallengeIndex}`)
      console.log(`   - Current challenge: ${challenges[nextChallengeIndex]?.title}`)
      console.log(`   - Challenge completed: ${challengeCompleted.value}`)
    } else {
      console.log('ℹ️ No completions found for user, starting from beginning')
    }
  } catch (error) {
    console.error('❌ Failed to restore user progress:', error)
  }
}

const submitFlag = async () => {
  const challenge = currentChallenge.value
  if (!challenge) return
  
  if (flagInput.value.trim().toLowerCase() === challenge.solution.toLowerCase()) {
    totalScore.value += challenge.points
    solvedChallenges.value.add(currentChallengeIndex.value)
    lastEarnedPoints.value = challenge.points
    completionMessage.value = 'CHALLENGE NEUTRALIZED'
    showCompletionScreen.value = true
    challengeCompleted.value = true
    
    
    const completionTime = Math.floor((Date.now() - challengeStartTime.value) / 1000)
    
    
    if (currentUser.value) {
      try {
        await $fetch('/api/challenges/complete', {
          method: 'POST',
          body: {
            userId: currentUser.value.id,
            challengeId: challenge.id,
            points: challenge.points,
            completionTime
          }
        })
      } catch (error) {
        console.error('Failed to save challenge completion:', error)
      }
    }
    
    
    showHint.value = false
    showTool.value = false
    flagInput.value = ''
    loginForm.username = ''
    loginForm.password = ''
    loginResult.value = ''
    cipherResults.value = ''
    
    
    challengeStartTime.value = Date.now()
  } else {
    
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
  const encryptedText = "PGS{PNRFNE_PVCURE_VF_RNFL}"
  const results = []
  
  results.push('CAESAR CIPHER ANALYSIS INITIATED...')
  results.push('='.repeat(50))
  results.push('')
  
  for (let i = 1; i <= 25; i++) {
    const decoded = caesarDecode(encryptedText, i)
    results.push(`SHIFT_${i.toString().padStart(2, '0')}: ${decoded}`)
    if (decoded.includes('CTF{')) {
      results.push(`🎯 >>> MATCH FOUND! SHIFT ${i} PRODUCES VALID FLAG <<<`)
      results.push('    ▲ This appears to be the correct decryption!')
      results.push('')
    }
  }
  
  results.push('')
  results.push('ANALYSIS COMPLETE. Look for CTF{...} pattern above.')
  results.push('') 
  results.push('END OF ANALYSIS RESULTS')
  results.push('') 
  results.push('')
  
  cipherResults.value = results.join('\n')
  
  // Ensure the container can scroll by forcing a reflow
  nextTick(() => {
    const toolOutput = document.querySelector('.tool-output') as HTMLElement
    if (toolOutput) {
      toolOutput.scrollTop = 0
      // Force browser to recognize scrollable content
      toolOutput.style.overflowY = 'scroll'
    }
  })
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

// Removed duplicate definition of initThreeJS
const initThreeJS = () => {
  try {
    if (!threeCanvas.value) {
      console.warn('Three.js canvas not available')
      return
    }
    
    
    if (renderer) {
      console.warn('Three.js already initialized')
      return
    }
    
    
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
    
    
    const t = Math.random()
    const colorType = Math.floor(Math.random() * 4) // 4 different neon color types
    
    if (colorType === 0) {
      // Light cyan/aqua
      colors[i * 3] = 0.3 + t * 0.2     // Red
      colors[i * 3 + 1] = 0.9 + t * 0.1 // Green  
      colors[i * 3 + 2] = 0.9 + t * 0.1 // Blue
    } else if (colorType === 1) {
      // Light green
      colors[i * 3] = 0.2 + t * 0.2     // Red
      colors[i * 3 + 1] = 0.9 + t * 0.1 // Green  
      colors[i * 3 + 2] = 0.3 + t * 0.2 // Blue
    } else if (colorType === 2) {
      // Light pink/magenta
      colors[i * 3] = 0.9 + t * 0.1     // Red
      colors[i * 3 + 1] = 0.3 + t * 0.2 // Green  
      colors[i * 3 + 2] = 0.8 + t * 0.2 // Blue
    } else {
      // Light purple
      colors[i * 3] = 0.7 + t * 0.2     // Red
      colors[i * 3 + 1] = 0.3 + t * 0.2 // Green  
      colors[i * 3 + 2] = 0.9 + t * 0.1 // Blue
    }
  }
  
  const geometry = new THREE.BufferGeometry()
  geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3))
  geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3))
  
  const material = new THREE.PointsMaterial({
    size: 0.8,
    vertexColors: true,
    transparent: true,
    opacity: 0.15,
    blending: THREE.AdditiveBlending
  })
  
  particles = new THREE.Points(geometry, material)
    scene.add(particles)
    
    
    particles.userData = { velocities }
    
    camera.position.z = 50
    
    animate()
    threeJsLoaded.value = true
  } catch (error) {
    console.error('Failed to initialize Three.js:', error)
   
    if (threeCanvas.value) {
      threeCanvas.value.style.display = 'none'
    }
    threeJsLoaded.value = false
  } finally {
    isLoading.value = false
  }
}

const animate = () => {
  try {
    if (!renderer || !scene || !camera) return
    
    animationId = requestAnimationFrame(animate)
    
    
    if (particles && particles.userData?.velocities && particles.geometry?.attributes?.position) {
      const positionAttr = particles.geometry.attributes.position
      const positions = positionAttr.array as Float32Array
      const velocities = particles.userData.velocities as Float32Array
      
      if (positions && velocities && positions.length === velocities.length) {
        for (let i = 0; i < positions.length - 2; i += 3) {
          
          const x = positions[i]
          const y = positions[i + 1]
          const z = positions[i + 2]
          const vx = velocities[i]
          const vy = velocities[i + 1]
          const vz = velocities[i + 2]
          
          if (x !== undefined && y !== undefined && z !== undefined && 
              vx !== undefined && vy !== undefined && vz !== undefined) {
            const newX = x + vx
            const newY = y + vy
            const newZ = z + vz
            
            positions[i] = newX
            positions[i + 1] = newY
            positions[i + 2] = newZ
            
            
            if (Math.abs(newX) > 40) velocities[i] = -vx
            if (Math.abs(newY) > 40) velocities[i + 1] = -vy
            if (Math.abs(newZ) > 40) velocities[i + 2] = -vz
          }
        }
        
        positionAttr.needsUpdate = true
        
        
        particles.rotation.x += 0.0005
        particles.rotation.y += 0.001
      }
    }
    
    renderer.render(scene, camera)
  } catch (error) {
    console.error('Animation error:', error)
    
    if (animationId) {
      cancelAnimationFrame(animationId)
      animationId = null
    }
  }
}

const handleResize = () => {
  if (!camera || !renderer) return
  
  camera.aspect = window.innerWidth / window.innerHeight
  camera.updateProjectionMatrix()
  renderer.setSize(window.innerWidth, window.innerHeight)
}


onMounted(async () => {
  console.log('🚀 Component mounted, starting initialization...')
  
 
  if (typeof window === 'undefined') {
    isLoading.value = false
    return
  }
  
  // Check for existing user session
  const savedUser = localStorage.getItem('ctf-user')
  console.log('💾 Saved user from localStorage:', savedUser)
  
  if (savedUser) {
    try {
      currentUser.value = JSON.parse(savedUser)
      console.log('👤 Current user set to:', currentUser.value)
      challengeStartTime.value = Date.now()
      
      console.log('🔄 About to restore user progress...')
      console.log('📊 Current challenge index BEFORE restoration:', currentChallengeIndex.value)
      console.log('🎯 Solved challenges BEFORE restoration:', Array.from(solvedChallenges.value))
      
      // Restore user's previous progress
      await restoreUserProgress(currentUser.value.id)
      
      console.log('✅ Progress restoration completed')
      console.log('📊 Current challenge index AFTER restoration:', currentChallengeIndex.value)
      console.log('🎯 Solved challenges AFTER restoration:', Array.from(solvedChallenges.value))
    } catch (error) {
      console.error('Error parsing saved user:', error)
      localStorage.removeItem('ctf-user')
      showNameModal.value = true
    }
  } else {
    console.log('❌ No saved user found, showing name modal')
    showNameModal.value = true
  }
  
  try {
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
   
    
    // Wait a bit for the DOM to be ready
    await new Promise(resolve => setTimeout(resolve, 100))
    
    initThreeJS()
    window.addEventListener('resize', handleResize)
  } catch (error) {
    console.error('Error during initialization:', error)
    isLoading.value = false
  }
})

onUnmounted(() => {
  
  if (animationId) {
    cancelAnimationFrame(animationId)
    animationId = null
  }
  
  
  if (renderer) {
    renderer.dispose()
    renderer = null
  }
  
  if (particles && particles.geometry) {
    particles.geometry.dispose()
  }
  
  if (particles && particles.material) {
    if (Array.isArray(particles.material)) {
      particles.material.forEach(material => material.dispose())
    } else {
      particles.material.dispose()
    }
  }
  
  particles = null
  scene = null
  camera = null
  
  
  window.removeEventListener('resize', handleResize)
})
</script>

<style scoped>
@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&family=Share+Tech+Mono&display=swap');

:root {
  --primary-color: #00ff88;
  --danger-color: #ff0000;
  --dark-bg: #050a14;
  --light-text: #e6f1ff;
  --dark-text: #8899a6;
  --card-bg: rgba(16, 24, 38, 0.8);
  --border-color: rgba(0, 255, 136, 0.2);
}

/* Ensure page can scroll */
:global(html, body) {
  overflow-y: auto !important;
  height: auto !important;
  scroll-behavior: smooth;
}

/* Global Styles */
.cyberpunk-container {
  min-height: 100vh;
  background: linear-gradient(180deg, #050a14 0%, #000 100%);
  color: #e6f1ff;
  font-family: 'Roboto', sans-serif;
  position: relative;
  overflow-y: auto;
  overflow-x: hidden;
  scroll-behavior: smooth;
}

/* Loading Screen */
.loading-screen {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: linear-gradient(180deg, #050a14 0%, #000 100%);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.loading-content {
  text-align: center;
  color: var(--primary-color);
}

.loading-spinner {
  width: 50px;
  height: 50px;
  border: 3px solid rgba(0, 255, 136, 0.3);
  border-top: 3px solid var(--primary-color);
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin: 0 auto 1rem;
}

.loading-text {
  font-family: 'Share Tech Mono', monospace;
  font-size: 0.9rem;
  letter-spacing: 2px;
  animation: pulse 2s ease-in-out infinite;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

@keyframes pulse {
  0%, 100% { opacity: 0.6; }
  50% { opacity: 1; }
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
  padding-bottom: 4rem;
  display: flex;
  flex-direction: column;
}

/* HUD Header */
.hud-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1.5rem 2rem;
  background: var(--card-bg);
  border: 1px solid var(--border-color);
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
  background: var(--dark-text);
  box-shadow: 0 0 10px rgba(136, 153, 166, 0.5);
}

.status-indicator.in_progress {
  background: var(--primary-color);
  box-shadow: 0 0 10px rgba(0, 255, 136, 0.5);
}

.status-indicator.complete {
  background: var(--primary-color);
  box-shadow: 0 0 10px rgba(0, 255, 136, 0.5);
}

.score-display {
  display: flex;
  gap: 2rem;
  align-items: center;
  font-weight: 600;
  font-size: 1rem;
}

.leaderboard-link {
  background: rgba(245, 158, 11, 0.1);
  border: 1px solid rgba(245, 158, 11, 0.3);
  border-radius: 6px;
  padding: 0.5rem 1rem;
  color: #f59e0b;
  text-decoration: none;
  font-weight: 600;
  font-size: 0.9rem;
  transition: all 0.3s ease;
  text-transform: uppercase;
  letter-spacing: 1px;
}

.leaderboard-link:hover {
  background: rgba(245, 158, 11, 0.2);
  border-color: rgba(245, 158, 11, 0.5);
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(245, 158, 11, 0.3);
}

.progress {
  color: #3b82f6;
}

/* Challenge Window */
.challenge-window {
  background: var(--card-bg);
  border: 1px solid var(--border-color);
  border-radius: 16px;
  max-width: 900px;
  margin: 0 auto;
  backdrop-filter: blur(10px);
  box-shadow: 
    0 20px 60px rgba(0, 0, 0, 0.4),
    0 8px 32px rgba(0, 255, 136, 0.1);
  transition: all 0.3s ease;
}

.challenge-window:hover {
  box-shadow: 
    0 24px 80px rgba(0, 0, 0, 0.5),
    0 12px 40px rgba(0, 255, 136, 0.15);
}

.window-header {
  background: rgba(0, 255, 136, 0.05);
  padding: 1.5rem 2rem;
  border-bottom: 1px solid var(--border-color);
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
  color: var(--primary-color);
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

/* Steganography Interface */
.stego-interface {
  background: rgba(255, 255, 255, 0.02);
  border: 1px solid rgba(99, 102, 241, 0.2);
  border-radius: 8px;
  padding: 2rem;
}

.image-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 1rem;
}

.stego-image {
  width: 300px;
  height: 200px;
  background: linear-gradient(45deg, #1a1a2e, #16213e);
  border: 2px solid rgba(99, 102, 241, 0.3);
  border-radius: 8px;
  object-fit: cover;
  cursor: pointer;
  transition: all 0.3s ease;
}

.stego-image:hover {
  border-color: #6366f1;
  box-shadow: 0 0 15px rgba(99, 102, 241, 0.3);
  transform: scale(1.02);
}

.image-hint {
  color: rgba(156, 163, 175, 0.8);
  font-size: 0.9rem;
  text-align: center;
  font-style: italic;
}

/* JavaScript Obfuscation Interface */
.js-obfuscation-interface {
  background: rgba(255, 255, 255, 0.02);
  border: 1px solid rgba(99, 102, 241, 0.2);
  border-radius: 8px;
  padding: 2rem;
}

.code-container {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.obfuscated-code {
  background: rgba(0, 0, 0, 0.4);
  border: 1px solid rgba(156, 163, 175, 0.3);
  border-radius: 8px;
  padding: 1.5rem;
  color: #10b981;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.85rem;
  line-height: 1.5;
  overflow-x: auto;
  white-space: pre;
}

.code-hint {
  color: rgba(156, 163, 175, 0.8);
  font-size: 0.9rem;
  text-align: center;
  font-style: italic;
  margin: 0;
}

/* Forensics Interface */
.forensics-interface {
  background: rgba(255, 255, 255, 0.02);
  border: 1px solid rgba(99, 102, 241, 0.2);
  border-radius: 8px;
  padding: 2rem;
}

.forensics-container {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.evidence-item {
  background: rgba(0, 0, 0, 0.3);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 1.5rem;
  transition: all 0.3s ease;
}

.evidence-item:hover {
  border-color: var(--primary-color);
  box-shadow: 0 0 10px rgba(0, 255, 136, 0.2);
}

.evidence-header {
  color: var(--primary-color);
  font-family: 'Share Tech Mono', monospace;
  font-weight: bold;
  margin-bottom: 1rem;
  font-size: 1rem;
}

.evidence-content {
  color: var(--light-text);
  line-height: 1.6;
}

.evidence-content p {
  margin: 0.5rem 0;
}

.hidden-data {
  opacity: 0.1;
  font-size: 0.8rem;
}

.forensics-hint {
  color: rgba(156, 163, 175, 0.8);
  font-size: 0.9rem;
  text-align: center;
  font-style: italic;
  margin: 1rem 0 0 0;
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
  position: relative;
}

.tool-interface::after {
  content: "🔽 SCROLL DOWN TO SEE MORE RESULTS 🔽";
  position: absolute;
  bottom: 0.5rem;
  right: 1rem;
  font-size: 0.8rem;
  color: rgba(99, 102, 241, 0.9);
  pointer-events: none;
  font-family: 'Inter', sans-serif;
  font-weight: 600;
  background: rgba(0, 0, 0, 0.7);
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  z-index: 10;
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
  padding: 1rem;
  font-family: 'JetBrains Mono', 'Courier New', monospace;
  font-size: 0.8rem;
  white-space: pre-line;
  word-wrap: break-word;
  /* Fixed height container */
  height: 300px;
  min-height: 300px;
  max-height: 300px;
  /* Force scrolling */
  overflow: auto;
  overflow-y: scroll;
  overflow-x: hidden;
  /* Styling */
  border: 2px solid rgba(99, 102, 241, 0.4);
  border-radius: 6px;
  color: #e0e6ed;
  /* Ensure it's a proper scroll container */
  display: block;
  position: relative;
  /* Scrollbar styling */
  scrollbar-width: thin;
  scrollbar-color: #6366f1 rgba(0, 0, 0, 0.3);
}

/* WebKit scrollbar styling for better visibility */
.tool-output::-webkit-scrollbar {
  width: 12px;
  background: rgba(0, 0, 0, 0.3);
}

.tool-output::-webkit-scrollbar-track {
  background: rgba(0, 0, 0, 0.4);
  border-radius: 6px;
  margin: 4px;
}

.tool-output::-webkit-scrollbar-thumb {
  background: rgba(99, 102, 241, 0.8);
  border-radius: 6px;
  border: 2px solid rgba(0, 0, 0, 0.4);
}

.tool-output::-webkit-scrollbar-thumb:hover {
  background: rgba(99, 102, 241, 1);
}

.tool-output::-webkit-scrollbar-thumb:active {
  background: rgba(139, 92, 246, 1);
}

.hint-btn, .tool-btn {
  background: rgba(0, 255, 136, 0.1);
  color: var(--primary-color);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  padding: 0.75rem 1.5rem;
  cursor: pointer;
  font-family: 'Share Tech Mono', monospace;
  font-weight: 600;
  transition: all 0.3s ease;
  font-size: 0.9rem;
}

.hint-btn:hover, .tool-btn:hover {
  background: rgba(0, 255, 136, 0.15);
  border-color: var(--primary-color);
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(0, 255, 136, 0.2);
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
  border: 2px solid var(--border-color);
  border-radius: 8px;
  color: var(--light-text);
  font-family: 'Share Tech Mono', monospace;
  font-size: 1rem;
  outline: none;
  transition: all 0.3s ease;
}

.flag-input:focus {
  border-color: var(--primary-color);
  box-shadow: 0 0 0 3px rgba(0, 255, 136, 0.1);
  background: rgba(0, 255, 136, 0.05);
}

.flag-input::placeholder {
  color: var(--dark-text);
}

.submit-btn {
  padding: 1rem 2rem;
  background: transparent;
  border: 1px solid var(--primary-color);
  border-radius: 8px;
  color: var(--primary-color);
  cursor: pointer;
  font-family: 'Share Tech Mono', monospace;
  font-weight: 700;
  font-size: 1rem;
  transition: all 0.3s ease;
  box-shadow: 0 4px 12px rgba(0, 255, 136, 0.3);
}

.submit-btn:hover:not(:disabled) {
  background: var(--primary-color);
  color: var(--dark-bg);
  box-shadow: 0 0 15px var(--primary-color);
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

/* Modal Styles */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100vw;
  height: 100vh;
  background: rgba(0, 0, 0, 0.9);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 10000;
  backdrop-filter: blur(8px);
}

.name-modal {
  background: var(--card-bg);
  border: 2px solid var(--border-color);
  border-radius: 12px;
  padding: 2.5rem;
  max-width: 500px;
  width: 90%;
  box-shadow: 0 20px 40px rgba(0, 0, 0, 0.8);
  animation: modalSlide 0.3s ease-out;
  position: relative;
  backdrop-filter: blur(10px);
}

.name-modal::before {
  content: '';
  position: absolute;
  top: -2px;
  left: -2px;
  right: -2px;
  bottom: -2px;
  background: linear-gradient(45deg, var(--primary-color), #00cc77, var(--danger-color), var(--primary-color));
  border-radius: 12px;
  z-index: -1;
  animation: borderGlow 3s ease-in-out infinite;
}

@keyframes modalSlide {
  from {
    opacity: 0;
    transform: translateY(-50px) scale(0.9);
  }
  to {
    opacity: 1;
    transform: translateY(0) scale(1);
  }
}

@keyframes borderGlow {
  0%, 100% { opacity: 0.8; }
  50% { opacity: 1; }
}

.modal-header {
  text-align: center;
  margin-bottom: 2rem;
}

.modal-title {
  color: var(--primary-color);
  font-family: 'Share Tech Mono', monospace;
  font-size: 1.5rem;
  font-weight: 700;
  margin-bottom: 0.5rem;
  text-transform: uppercase;
  letter-spacing: 2px;
}

.modal-subtitle {
  color: var(--dark-text);
  font-size: 0.9rem;
  margin: 0;
}

.modal-content {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.input-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.input-group label {
  color: #6366f1;
  font-weight: 600;
  font-size: 0.85rem;
  text-transform: uppercase;
  letter-spacing: 1px;
}

.name-input {
  background: rgba(0, 0, 0, 0.4);
  border: 2px solid var(--border-color);
  border-radius: 6px;
  padding: 1rem;
  color: var(--light-text);
  font-size: 1rem;
  font-family: 'Share Tech Mono', monospace;
  transition: all 0.3s ease;
}

.name-input:focus {
  outline: none;
  border-color: var(--primary-color);
  box-shadow: 0 0 15px rgba(0, 255, 136, 0.3);
  background: rgba(0, 0, 0, 0.6);
}

.name-input::placeholder {
  color: var(--dark-text);
}

.register-btn {
  background: transparent;
  border: 1px solid var(--primary-color);
  border-radius: 6px;
  padding: 1rem 2rem;
  color: var(--primary-color);
  font-family: 'Share Tech Mono', monospace;
  font-weight: 700;
  font-size: 0.9rem;
  text-transform: uppercase;
  letter-spacing: 1px;
  cursor: pointer;
  transition: all 0.3s ease;
  position: relative;
  overflow: hidden;
}

.register-btn:hover:not(:disabled) {
  background: var(--primary-color);
  color: var(--dark-bg);
  box-shadow: 0 0 15px var(--primary-color);
  transform: translateY(-2px);
}

.register-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  transform: none;
}

.register-btn::before {
  content: '';
  position: absolute;
  top: 0;
  left: -100%;
  width: 100%;
  height: 100%;
  background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
  transition: left 0.5s;
}

.register-btn:hover:not(:disabled)::before {
  left: 100%;
}
</style>