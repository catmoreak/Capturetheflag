<template>
  <div class="hacker-theme">
    <canvas ref="threeCanvas" class="three-canvas"></canvas>
    <div class="content-overlay">
      <header class="main-header">
        <div class="container">
          <div class="logo">CTF Challenge</div>
          <nav>
            <NuxtLink to="/">Home</NuxtLink>
            <NuxtLink to="/challenges">Challenges</NuxtLink>
            <NuxtLink to="/leaderboard" class="active">Leaderboard</NuxtLink>
          </nav>
        </div>
      </header>
      <main class="container" style="padding-top: 7rem;">
        <section class="features">
          <div class="feature-card is-visible" style="max-width: 700px; margin: 0 auto;">
            <h3>🏆 Leaderboard</h3>
            <button @click="refreshLeaderboard" class="btn" :disabled="isLoadingLeaderboard" style="float:right; margin-top:-2.5rem;">
              <span :class="{ 'spinning': isLoadingLeaderboard }">{{ isLoadingLeaderboard ? '⟳' : '↻'  }}</span>    Refresh
            </button>
            <div v-if="leaderboard.length > 0">
              <div class="features" style="padding:0;">
                <div class="container" style="padding:0;">
                  <div class="features" style="padding:0;">
                    <div class="feature-card is-visible" style="background:none;box-shadow:none;padding:0;">
                      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:2rem;">
                        <div>
                          <div class="ctf-stat-value">{{ leaderboard.length }}</div>
                          <div class="ctf-stat-label">Players</div>
                        </div>
                        <div>
                          <div class="ctf-stat-value">{{ topScore }}</div>
                          <div class="ctf-stat-label">Top Score</div>
                        </div>
                        <div>
                          <div class="ctf-stat-value">{{ completedChallenges }}</div>
                          <div class="ctf-stat-label">Total Solves</div>
                        </div>
                      </div>
                      <div style="overflow-x:auto;">
                        <table style="width:100%;border-collapse:collapse;">
                          <thead>
                            <tr style="background:rgba(0,255,136,0.08);color:var(--primary-color);">
                              <th>#</th>
                              <th>Player</th>
                              <th>Score</th>
                              <th>Solved</th>
                              <th>Avg Time</th>
                              <th>Total Time</th>
                              <th>Joined</th>
                            </tr>
                          </thead>
                          <tbody>
                            <tr v-for="entry in leaderboard" :key="entry.id" :style="entry.id === currentUser?.id ? 'background:rgba(0,255,136,0.08);color:var(--primary-color);' : ''">
                              <td>
                                <span v-if="entry.rank === 1">🥇</span>
                                <span v-else-if="entry.rank === 2">🥈</span>
                                <span v-else-if="entry.rank === 3">🥉</span>
                                <span v-else>{{ entry.rank }}</span>
                              </td>
                              <td>{{ entry.name }}</td>
                              <td>{{ entry.totalPoints }}</td>
                              <td>{{ entry.totalChallenges }}/6</td>
                              <td>{{ entry.averageTime }}s</td>
                              <td>{{ formatTime(entry.totalTime) }}</td>
                              <td>{{ formatDate(entry.joinedAt) }}</td>
                            </tr>
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <div v-else-if="!isLoadingLeaderboard" style="text-align:center;padding:2rem 0;">
              <div class="ctf-empty-icon">📊</div>
              <h3>No Data Yet</h3>
              <p>Be the first to complete challenges and appear on the leaderboard!</p>
              <NuxtLink to="/" class="btn">Start Challenges</NuxtLink>
            </div>
            <div v-if="isLoadingLeaderboard" style="text-align:center;padding:2rem 0;">
              <div class="ctf-spinner"></div>
              <p>Loading leaderboard data...</p>
            </div>
          </div>
        </section>
        <section v-if="currentUser" class="features" style="padding:0;">
          <div class="feature-card is-visible" style="max-width:500px;margin:2rem auto 0 auto;">
            <h3>Your Stats</h3>
            <div style="display:flex;flex-direction:column;align-items:center;gap:1.5rem;">
              <div style="text-align:center;">
                <div style="font-size:1.2rem;font-weight:700;color:var(--primary-color);margin-bottom:0.5rem;">{{ currentUser.name }}</div>
                <div v-if="userRank" style="color:var(--dark-text);font-size:0.95rem;">Rank #{{ userRank }}</div>
              </div>
              <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;">
                <div>
                  <div class="ctf-stat-value">{{ userStats.totalPoints }}</div>
                  <div class="ctf-stat-label">Points</div>
                </div>
                <div>
                  <div class="ctf-stat-value">{{ userStats.completedChallenges }}</div>
                  <div class="ctf-stat-label">Completed</div>
                </div>
                <div>
                  <div class="ctf-stat-value">{{ userStats.averageTime }}s</div>
                  <div class="ctf-stat-label">Avg Time</div>
                </div>
              </div>
            </div>
          </div>
        </section>
      </main>
      <footer class="main-footer">
        <div class="container">
          &copy; {{ new Date().getFullYear() }} CTF Challenge. All rights reserved.
        </div>
      </footer>
    </div>
</div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref, computed } from 'vue'
import * as THREE from 'three'

let scene: THREE.Scene
  let camera: THREE.PerspectiveCamera
  let renderer: THREE.WebGLRenderer
  let composer: any
  let clock = new THREE.Clock()
  let packets: any[] = []
  let collisionEffects: any[] = []
  let cursorLight: THREE.PointLight
  let raycaster: THREE.Raycaster
  let mousePlane: THREE.Mesh
  let mouse = { x: 0, y: 0 }
  let lookAtTarget = new THREE.Vector3(0, 20, 0)
  const GRID_SIZE = 400

  const threeCanvas = ref<HTMLCanvasElement | null>(null)
  const leaderboard = ref<any[]>([])
  const isLoadingLeaderboard = ref(false)
  const currentUser = ref<any>(null)
  const topScore = computed(() => leaderboard.value.length > 0 ? leaderboard.value[0].totalPoints : 0)
  const completedChallenges = computed(() => leaderboard.value.reduce((total, user) => total + user.totalChallenges, 0))
  const userRank = computed(() => {
    if (!currentUser.value) return null
    const user = leaderboard.value.find(u => u.id === currentUser.value.id)
    return user ? user.rank : null
  })
  const userStats = computed(() => {
    if (!currentUser.value) return { totalPoints: 0, completedChallenges: 0, averageTime: 0 }
    const user = leaderboard.value.find(u => u.id === currentUser.value.id)
    return user ? {
      totalPoints: user.totalPoints,
      completedChallenges: user.totalChallenges,
      averageTime: user.averageTime
    } : { totalPoints: 0, completedChallenges: 0, averageTime: 0 }
  })
  const refreshLeaderboard = async () => {
    if (isLoadingLeaderboard.value) return
    isLoadingLeaderboard.value = true
    try {
      const response = await $fetch('/api/leaderboard') as any
      if (response.success) {
        leaderboard.value = response.leaderboard
      }
    } catch (error) {
      console.error('Failed to fetch leaderboard:', error)
    } finally {
      isLoadingLeaderboard.value = false
    }
  }
  const formatTime = (seconds: number) => {
    const minutes = Math.floor(seconds / 60)
    const remainingSeconds = seconds % 60
    return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`
  }
  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString()
  }

  function createParticleSystem(color: number, count: number, size: number, speed: number) {
    const geom = new THREE.BufferGeometry()
    const positions = new Float32Array(count * 3)
    const velocities = new Float32Array(count * 3)
    for (let i = 0; i < count; i++) {
      positions.set([0,0,0], i * 3)
      const v = new THREE.Vector3(
        (Math.random() - 0.5) * speed,
        Math.random() * speed * 1.5,
        (Math.random() - 0.5) * speed
      )
      velocities.set([v.x, v.y, v.z], i * 3)
    }
    geom.setAttribute('position', new THREE.BufferAttribute(positions, 3))
    geom.setAttribute('velocity', new THREE.BufferAttribute(velocities, 3))
    const mat = new THREE.PointsMaterial({ 
      color, 
      size, 
      blending: THREE.AdditiveBlending, 
      transparent: true, 
      opacity: 1.0, 
      sizeAttenuation: true 
    })
    const points = new THREE.Points(geom, mat)
    points.visible = false
    return points
  }
  function createCollisionEffect() {
    const redFire = createParticleSystem(0xff4500, 500, 2, 8)
    const yellowFire = createParticleSystem(0xffa500, 500, 2.5, 10)
    const whiteSmoke = createParticleSystem(0xffffff, 800, 2.5, 5)
    return { redFire, yellowFire, whiteSmoke, life: 0, visible: false }
  }
  function triggerCollision() {
    const effect = collisionEffects.find(e => !e.visible)
    if (effect) {
      const x = (Math.random() - 0.5) * (GRID_SIZE * 0.8)
      const z = (Math.random() * (GRID_SIZE / 2))
      const position = new THREE.Vector3(x, 1, z)
      Object.values(effect).forEach((particleSystem: any) => {
        if (particleSystem instanceof THREE.Points) {
          particleSystem.position.copy(position)
          const posAttr = particleSystem.geometry.getAttribute('position')
          posAttr.needsUpdate = true
          for(let i=0; i<posAttr.count; i++) {
            posAttr.setXYZ(i, 0, 0, 0)
          }
          particleSystem.visible = true
        }
      })
      effect.life = 0
      effect.visible = true
    }
  }

  const animate = () => {
    requestAnimationFrame(animate)
    const delta = clock.getDelta()
    const time = clock.getElapsedTime()
    packets.forEach(p => {
      p.position.z += p.userData.velocity * 60 * delta
      if (p.userData.velocity > 0 && p.position.z > GRID_SIZE / 2) p.position.z = -GRID_SIZE / 2
      if (p.userData.velocity < 0 && p.position.z < -GRID_SIZE / 2) p.position.z = GRID_SIZE / 2
    })
    if (Math.random() < 0.001) triggerCollision()
    collisionEffects.forEach(e => {
      if (e.visible) {
        e.life += delta
        ;['redFire', 'yellowFire', 'whiteSmoke'].forEach(key => {
          const ps = e[key]
          const posAttr = ps.geometry.getAttribute('position')
          const velAttr = ps.geometry.getAttribute('velocity')
          for (let i = 0; i < posAttr.count; i++) {
            posAttr.array[i*3] += velAttr.array[i*3] * delta
            posAttr.array[i*3+1] += velAttr.array[i*3+1] * delta
            posAttr.array[i*3+2] += velAttr.array[i*3+2] * delta
          }
          posAttr.needsUpdate = true
          ps.material.opacity = 1.0 - (e.life / 1.5)
        })
        if (e.life >= 1.5) e.visible = false
      }
    })
    camera.position.x = Math.sin(time * 0.1) * 90
    camera.position.z = 130 + Math.cos(time * 0.12) * 60
    camera.position.y = 50 + Math.sin(time * 0.2) * 15
    raycaster.setFromCamera(new THREE.Vector2(mouse.x, mouse.y), camera)
    const intersects = raycaster.intersectObject(mousePlane)
    if (intersects.length > 0 && intersects[0]) {
      const intersectPoint = intersects[0].point
      cursorLight.position.copy(intersectPoint)
      cursorLight.position.y = 10
    }
    lookAtTarget.x = (mouse.x * 40)
    lookAtTarget.y = 20 + (-mouse.y * 20)
    lookAtTarget.z = 0
    camera.lookAt(lookAtTarget)
    if (composer) composer.render()
    else renderer.render(scene, camera)
  }

  const onWindowResize = () => {
    const width = window.innerWidth
    const height = window.innerHeight
    camera.aspect = width / height
    camera.updateProjectionMatrix()
    renderer.setSize(width, height)
    if (composer) composer.setSize(width, height)
  }
  const onMouseMove = (event: MouseEvent) => {
    mouse.x = (event.clientX / window.innerWidth) * 2 - 1
    mouse.y = -(event.clientY / window.innerHeight) * 2 + 1
  }

  onMounted(async () => {
    if (typeof window !== 'undefined') {
      const savedUser = localStorage.getItem('ctf-user')
      if (savedUser) {
        try {
          currentUser.value = JSON.parse(savedUser)
        } catch (error) {
          console.error('Error parsing saved user:', error)
        }
      }
      
      scene = new THREE.Scene()
      scene.fog = new THREE.Fog(0x050a14, 150, 350)
      camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 0.1, 1000)
      camera.position.set(0, 60, 130)
      renderer = new THREE.WebGLRenderer({ canvas: threeCanvas.value!, antialias: true })
      renderer.setSize(window.innerWidth, window.innerHeight)
      renderer.setClearColor(0x050a14, 1)
      scene.add(new THREE.AmbientLight(0x404040, 0.5))
      cursorLight = new THREE.PointLight(0x00ff00, 15, 80, 2)
      scene.add(cursorLight)
      raycaster = new THREE.Raycaster()
      mousePlane = new THREE.Mesh(
        new THREE.PlaneGeometry(GRID_SIZE, GRID_SIZE),
        new THREE.MeshBasicMaterial({visible: false})
      )
      mousePlane.rotation.x = -Math.PI / 2
      scene.add(mousePlane)
      const gridHelper = new THREE.GridHelper(GRID_SIZE, 20, 0x00ff88, 0xff0000)
      ;(gridHelper.material as THREE.Material).transparent = true
      ;(gridHelper.material as THREE.Material).opacity = 0.1
      scene.add(gridHelper)
      const greenPacketMat = new THREE.MeshStandardMaterial({ color: 0x00ff88, emissive: 0x00ff88, emissiveIntensity: 2 })
      const redPacketMat = new THREE.MeshStandardMaterial({ color: 0xff0000, emissive: 0xff0000, emissiveIntensity: 2 })
      const packetGeom = new THREE.BoxGeometry(1, 1, 5)
      for (let i = 0; i < 100; i++) {
        const isAttacker = i >= 50
        const mat = isAttacker ? redPacketMat : greenPacketMat
        const packet = new THREE.Mesh(packetGeom, mat)
        packet.position.set((Math.random() - 0.5) * GRID_SIZE, 0.5, (Math.random() - 0.5) * GRID_SIZE)
        packet.userData.velocity = isAttacker ? (Math.random() * -1 - 0.5) : (Math.random() * 1 + 0.5)
        packets.push(packet)
        scene.add(packet)
      }
      for (let i=0; i<10; i++) {
        const effect = createCollisionEffect()
        collisionEffects.push(effect)
        scene.add(effect.redFire, effect.yellowFire, effect.whiteSmoke)
      }
      window.addEventListener('resize', onWindowResize)
      window.addEventListener('mousemove', onMouseMove)
      animate()
    }
    await refreshLeaderboard()
  })
  onUnmounted(() => {
    window.removeEventListener('resize', onWindowResize)
    window.removeEventListener('mousemove', onMouseMove)
  })


</script>

<style scoped>
.hacker-theme {
  position: relative;
  overflow: hidden;
  height: 100vh;
  background: linear-gradient(180deg, #050a14 0%, #000 100%);
}

.three-canvas {
  display: block;
  width: 100%;
  height: 100%;
}

.content-overlay {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  display: flex;
  flex-direction: column;
  z-index: 1;
}

.main-header {
  position: relative;
  z-index: 2;
  padding: 1rem 0;
}

.logo {
  font-size: 1.5rem;
  font-weight: 700;
  color: var(--primary-color);
}

nav {
  display: flex;
  gap: 2rem;
}

nav a {
  color: #fff;
  text-decoration: none;
  font-weight: 500;
}

nav a.active {
  color: var(--primary-color);
}

.container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 0 1rem;
}

.features {
  margin: 4rem 0;
}

.feature-card {
  background: rgba(255, 255, 255, 0.05);
  border-radius: 8px;
  padding: 2rem;
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
  transition: transform 0.3s;
}

.feature-card:hover {
  transform: translateY(-2px);
}

.ctf-stat-value {
  font-size: 2rem;
  font-weight: 700;
  color: #fff;
}

.ctf-stat-label {
  font-size: 0.875rem;
  color: #ccc;
}

table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 1rem;
}

th, td {
  padding: 0.75rem;
  text-align: left;
  border-bottom: 1px solid rgba(255, 255, 255, 0.1);
}

th {
  background: rgba(255, 255, 255, 0.1);
  color: #fff;
}

.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 0.5rem 1rem;
  background: var(--primary-color);
  color: #fff;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  transition: background 0.3s;
}

.btn:hover {
  background: rgba(255, 255, 255, 0.1);
}

.main-footer {
  position: relative;
  z-index: 2;
  padding: 1rem 0;
  text-align: center;
  color: #ccc;
}

.ctf-empty-icon {
  font-size: 3rem;
  color: var(--primary-color);
  margin-bottom: 1rem;
}

.ctf-spinner {
  border: 4px solid rgba(255, 255, 255, 0.1);
  border-top: 4px solid var(--primary-color);
  border-radius: 50%;
  width: 2rem;
  height: 2rem;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}
</style>