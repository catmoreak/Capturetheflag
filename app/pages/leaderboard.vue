<template>
  <div class="hacker-theme">
    <canvas ref="threeCanvas" class="three-canvas"></canvas>
    <div class="content-overlay">
      <header class="main-header">
        <div class="container">
          <div class="logo">CTF_Platform</div>
          <nav>
            <NuxtLink to="/">Home</NuxtLink>
            <NuxtLink to="/challenges">Challenges</NuxtLink>
            <NuxtLink to="/leaderboard" class="active">Leaderboard</NuxtLink>
          </nav>
        </div>
      </header>

      <main class="main-content">
        <div class="container">
          <!-- Page Header -->
          <div class="page-header">
            <h1 class="page-title">🏆 Leaderboard</h1>
            <p class="page-subtitle">Track your progress and compete with fellow hackers</p>
          </div>

          <!-- Statistics Overview -->
          <!-- <div v-if="leaderboard.length > 0" class="stats-overview">
            <div class="stat-card">
              <div class="stat-icon">👥</div>
              <div class="stat-content">
                <div class="stat-value">{{ leaderboard.length }}</div>
                <div class="stat-label">Active Players</div>
              </div>
            </div>
            <div class="stat-card">
              <div class="stat-icon">🎯</div>
              <div class="stat-content">
                <div class="stat-value">{{ topScore }}</div>
                <div class="stat-label">Top Score</div>
              </div>
            </div>
            <div class="stat-card">
              <div class="stat-icon">✅</div>
              <div class="stat-content">
                <div class="stat-value">{{ completedChallenges }}</div>
                <div class="stat-label">Total Solves</div>
              </div>
            </div>
          </div> -->

          <!-- Leaderboard Section -->
          <div class="leaderboard-section">
            <div class="section-header">
              <h2>Rankings</h2>
              <button @click="refreshLeaderboard" class="refresh-btn" :disabled="isLoadingLeaderboard">
                <span :class="{ 'spinning': isLoadingLeaderboard }">{{ isLoadingLeaderboard ? '⟳' : '↻' }}</span>
                Refresh
              </button>
            </div>

            <!-- Loading State -->
            <div v-if="isLoadingLeaderboard" class="loading-state">
              <div class="loading-spinner"></div>
              <p>Loading leaderboard data...</p>
            </div>

            <!-- Empty State -->
            <div v-else-if="leaderboard.length === 0" class="empty-state">
              <div class="empty-icon">📊</div>
              <h3>No Data Yet</h3>
              <p>Be the first to complete challenges and claim the top spot!</p>
              <NuxtLink to="/challenges" class="cta-btn">Start Hacking</NuxtLink>
            </div>

            <!-- Leaderboard Table -->
            <div v-else class="leaderboard-table-container">
              <table class="leaderboard-table">
                <thead>
                  <tr>
                    <th @click="sortBy('rank')" class="sortable">
                      Rank
                      <span class="sort-icon" :class="{ 'active': sortField === 'rank', 'desc': sortDirection === 'desc' }">↕</span>
                    </th>
                    <th @click="sortBy('name')" class="sortable">
                      Player
                      <span class="sort-icon" :class="{ 'active': sortField === 'name', 'desc': sortDirection === 'desc' }">↕</span>
                    </th>
                    <th @click="sortBy('totalPoints')" class="sortable">
                      Score
                      <span class="sort-icon" :class="{ 'active': sortField === 'totalPoints', 'desc': sortDirection === 'desc' }">↕</span>
                    </th>
                    <th @click="sortBy('solvedChallenges')" class="sortable">
                      Solved
                      <span class="sort-icon" :class="{ 'active': sortField === 'solvedChallenges', 'desc': sortDirection === 'desc' }">↕</span>
                    </th>
                    <th @click="sortBy('averageTime')" class="sortable">
                      Avg Time
                      <span class="sort-icon" :class="{ 'active': sortField === 'averageTime', 'desc': sortDirection === 'desc' }">↕</span>
                    </th>
                    <th>Total Time</th>
                    <th>Joined</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="entry in sortedLeaderboard" :key="entry.id"
                      :class="{ 'current-user': entry.id === currentUser?.id, 'top-three': entry.rank <= 3 }">
                    <td class="rank-cell">
                      <span v-if="entry.rank === 1" class="rank-badge gold">🥇</span>
                      <span v-else-if="entry.rank === 2" class="rank-badge silver">🥈</span>
                      <span v-else-if="entry.rank === 3" class="rank-badge bronze">🥉</span>
                      <span v-else class="rank-number">{{ entry.rank }}</span>
                    </td>
                    <td class="player-cell">
                      <div class="player-info">
                        <span class="player-name">{{ entry.name }}</span>
                        <span v-if="entry.id === currentUser?.id" class="you-badge">YOU</span>
                      </div>
                    </td>
                    <td class="score-cell">{{ entry.totalPoints.toLocaleString() }}</td>
                    <td class="solved-cell">{{ entry.solvedChallenges }}/8</td>
                    <td class="time-cell">{{ entry.averageTime }}s</td>
                    <td class="time-cell">{{ formatTime(entry.totalTime) }}</td>
                    <td class="date-cell">{{ formatDate(entry.joinedAt) }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <!-- User Stats Section -->
          <div v-if="currentUser && leaderboard.length > 0" class="user-stats-section">
            <div class="user-stats-card">
              <h3>Your Performance</h3>
              <div class="user-header" >
                <div class="user-avatar">{{ currentUser.name.charAt(0).toUpperCase() }}</div>
                <div class="user-info">
                  <div class="user-name">{{ currentUser.name }}</div>
                  <div class="user-rank">Rank #{{ userRank }}</div>
                </div>
              </div>
              <div class="user-stats-grid">
                <div class="user-stat">
                  <div class="stat-value">{{ userStats.totalPoints.toLocaleString() }}</div>
                  <div class="stat-label">Total Points</div>
                </div>
                <div class="user-stat">
                  <div class="stat-value">{{ userStats.completedChallenges }}</div>
                  <div class="stat-label">Challenges Solved</div>
                </div>
                <div class="user-stat">
                  <div class="stat-value">{{ userStats.averageTime }}s</div>
                  <div class="stat-label">Average Time</div>
                </div>
              </div>
            </div>
          </div>
        </div>
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

definePageMeta({
  title: 'Leaderboard - CTF_Platform'
})

useHead({
  title: 'Leaderboard - CTF_Platform',
  meta: [
    { property: 'og:title', content: 'Leaderboard - CTF_Platform' },
    { property: 'og:description', content: 'Track your progress and compete with fellow hackers on the CTF_Platform leaderboard.' },
    { property: 'og:type', content: 'website' },
    { property: 'og:url', content: 'https://capturetheflag.vercel.app/leaderboard' }
  ]
})

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
  const sortField = ref<string>('rank')
  const sortDirection = ref<'asc' | 'desc'>('asc')

  const topScore = computed(() => leaderboard.value.length > 0 ? leaderboard.value[0].totalPoints : 0)
  const completedChallenges = computed(() => leaderboard.value.reduce((total, user) => total + user.solvedChallenges, 0))
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
      completedChallenges: user.solvedChallenges,
      averageTime: user.averageTime
    } : { totalPoints: 0, completedChallenges: 0, averageTime: 0 }
  })
  const sortedLeaderboard = computed(() => {
    return [...leaderboard.value].sort((a, b) => {
      let aVal = a[sortField.value]
      let bVal = b[sortField.value]

      if (sortField.value === 'name') {
        aVal = aVal.toLowerCase()
        bVal = bVal.toLowerCase()
      }

      if (sortDirection.value === 'asc') {
        return aVal > bVal ? 1 : -1
      } else {
        return aVal < bVal ? 1 : -1
      }
    })
  })

  const sortBy = (field: string) => {
    if (sortField.value === field) {
      sortDirection.value = sortDirection.value === 'asc' ? 'desc' : 'asc'
    } else {
      sortField.value = field
      sortDirection.value = 'asc'
    }
  }
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
   


</script>

<style scoped>
.hacker-theme {
  position: relative;
  overflow: hidden;
  min-height: 100vh;
  background: linear-gradient(180deg, #050a14 0%, #000 100%);
}

.three-canvas {
  display: block;
  width: 100%;
  height: 100%;
  position: fixed;
  top: 0;
  left: 0;
  z-index: 0;
}

.content-overlay {
  position: relative;
  z-index: 1;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

.main-header {
  position: relative;
  z-index: 2;
  padding: 1rem 0;
  backdrop-filter: blur(10px);
  background: rgba(5, 10, 20, 0.8);
  border-bottom: 1px solid rgba(0, 255, 136, 0.1);
}

.logo {
  font-size: 1.5rem;
  font-weight: 700;
  color: var(--primary-color);
  text-shadow: 0 0 10px rgba(0, 255, 136, 0.5);
}

nav {
  display: flex;
  gap: 2rem;
}

nav a {
  color: #fff;
  text-decoration: none;
  font-weight: 500;
  transition: color 0.3s;
}

nav a:hover, nav a.active {
  color: var(--primary-color);
  text-shadow: 0 0 10px rgba(0, 255, 136, 0.5);
}

.container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 0 1rem;
}

.main-content {
  flex: 1;
  padding: 2rem 0;
}

/* Page Header */
.page-header {
  text-align: center;
  margin-bottom: 3rem;
}

.page-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #fff;
  margin-bottom: 0.5rem;
  text-shadow: 0 0 20px rgba(0, 255, 136, 0.3);
}

.page-subtitle {
  font-size: 1.1rem;
  color: #ccc;
  max-width: 600px;
  margin: 0 auto;
}

/* Statistics Overview */
.stats-overview {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1.5rem;
  margin-bottom: 3rem;
}

.stat-card {
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(0, 255, 136, 0.1);
  border-radius: 12px;
  padding: 1.5rem;
  display: flex;
  align-items: center;
  gap: 1rem;
  backdrop-filter: blur(10px);
  transition: all 0.3s;
}

.stat-card:hover {
  transform: translateY(-2px);
  border-color: rgba(0, 255, 136, 0.3);
  box-shadow: 0 8px 25px rgba(0, 255, 136, 0.1);
}

.stat-icon {
  font-size: 2rem;
  width: 60px;
  height: 60px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgba(0, 255, 136, 0.1);
  border-radius: 50%;
}

.stat-content {
  flex: 1;
}

.stat-value {
  font-size: 2rem;
  font-weight: 700;
  color: #fff;
  margin-bottom: 0.25rem;
}

.stat-label {
  font-size: 0.9rem;
  color: #ccc;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

/* Leaderboard Section */
.leaderboard-section {
  background: rgba(255, 255, 255, 0.03);
  border: 1px solid rgba(0, 255, 136, 0.1);
  border-radius: 16px;
  padding: 2rem;
  backdrop-filter: blur(10px);
  margin-bottom: 2rem;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 2rem;
}

.section-header h2 {
  font-size: 1.8rem;
  font-weight: 600;
  color: #fff;
  margin: 0;
}

.refresh-btn {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1.5rem;
  background: rgba(0, 255, 136, 0.1);
  border: 1px solid rgba(0, 255, 136, 0.3);
  border-radius: 8px;
  color: var(--primary-color);
  cursor: pointer;
  transition: all 0.3s;
  font-weight: 500;
}

.refresh-btn:hover:not(:disabled) {
  background: rgba(0, 255, 136, 0.2);
  transform: translateY(-1px);
}

.refresh-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.spinning {
  animation: spin 1s linear infinite;
}

/* Loading State */
.loading-state {
  text-align: center;
  padding: 3rem;
}

.loading-spinner {
  border: 3px solid rgba(255, 255, 255, 0.1);
  border-top: 3px solid var(--primary-color);
  border-radius: 50%;
  width: 40px;
  height: 40px;
  animation: spin 1s linear infinite;
  margin: 0 auto 1rem;
}

.loading-state p {
  color: #ccc;
  font-size: 1.1rem;
}

/* Empty State */
.empty-state {
  text-align: center;
  padding: 3rem;
}

.empty-icon {
  font-size: 4rem;
  margin-bottom: 1rem;
}

.empty-state h3 {
  color: #fff;
  font-size: 1.5rem;
  margin-bottom: 0.5rem;
}

.empty-state p {
  color: #ccc;
  font-size: 1.1rem;
  margin-bottom: 2rem;
}

.cta-btn {
  display: inline-flex;
  align-items: center;
  padding: 1rem 2rem;
  background: var(--primary-color);
  color: #000;
  text-decoration: none;
  border-radius: 8px;
  font-weight: 600;
  transition: all 0.3s;
}

.cta-btn:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 25px rgba(0, 255, 136, 0.3);
}

/* Leaderboard Table */
.leaderboard-table-container {
  overflow-x: auto;
  border-radius: 8px;
  background: rgba(0, 0, 0, 0.2);
}

.leaderboard-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.95rem;
}

.leaderboard-table thead th {
  background: rgba(0, 255, 136, 0.1);
  color: var(--primary-color);
  padding: 1rem;
  text-align: left;
  font-weight: 600;
  border-bottom: 1px solid rgba(0, 255, 136, 0.2);
  position: sticky;
  top: 0;
  z-index: 1;
}

.sortable {
  cursor: pointer;
  user-select: none;
  transition: background 0.3s;
}

.sortable:hover {
  background: rgba(0, 255, 136, 0.15);
}

.sort-icon {
  margin-left: 0.5rem;
  opacity: 0.5;
  transition: opacity 0.3s;
}

.sort-icon.active {
  opacity: 1;
}

.sort-icon.desc {
  transform: rotate(180deg);
}

.leaderboard-table tbody td {
  padding: 1rem;
  border-bottom: 1px solid rgba(255, 255, 255, 0.05);
  color: #fff;
  transition: background 0.3s;
}

.leaderboard-table tbody tr:hover {
  background: rgba(255, 255, 255, 0.02);
}

.leaderboard-table tbody tr.current-user {
  background: rgba(0, 255, 136, 0.1);
  border-left: 3px solid var(--primary-color);
}

.leaderboard-table tbody tr.top-three {
  background: rgba(255, 215, 0, 0.05);
}

.rank-cell {
  width: 80px;
  text-align: center;
}

.rank-badge {
  font-size: 1.2rem;
}

.rank-number {
  font-weight: 600;
  color: var(--primary-color);
}

.player-cell {
  min-width: 150px;
}

.player-info {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.player-name {
  font-weight: 500;
}

.you-badge {
  background: var(--primary-color);
  color: #000;
  padding: 0.2rem 0.5rem;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
}

.score-cell {
  font-weight: 600;
  color: var(--primary-color);
  font-family: 'Courier New', monospace;
}

.solved-cell {
  color: #4ade80;
}

.time-cell {
  font-family: 'Courier New', monospace;
}

.date-cell {
  color: #94a3b8;
}

/* User Stats Section */
.user-stats-section {
  margin-top: 2rem;
}

.user-stats-card {
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(0, 255, 136, 0.1);
  border-radius: 16px;
  padding: 2rem;
  backdrop-filter: blur(10px);
  max-width: 500px;
  margin: 0 auto;
}

.user-stats-card h3 {
  color: #fff;
  font-size: 1.5rem;
  margin-bottom: 1.5rem;
  text-align: center;
}

.user-header {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 1rem;
  margin-bottom: 1.5rem;
}

.user-avatar {
  width: 60px;
  height: 60px;
  background: var(--primary-color);
  color: #000;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  font-size: 1.5rem;
}

.user-name {
  font-size: 1.2rem;
  font-weight: 600;
  color: #fff;
  margin-bottom: 0.25rem;
}

.user-rank {
  color: var(--primary-color);
  font-weight: 500;
}

.user-stats-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1rem;
}

.user-stat {
  text-align: center;
  padding: 1rem;
  background: rgba(255, 255, 255, 0.03);
  border-radius: 8px;
  border: 1px solid rgba(255, 255, 255, 0.05);
}

.user-stat .stat-value {
  font-size: 1.5rem;
  font-weight: 700;
  color: var(--primary-color);
  margin-bottom: 0.25rem;
}

.user-stat .stat-label {
  font-size: 0.85rem;
  color: #ccc;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

/* Footer */
.main-footer {
  position: relative;
  z-index: 2;
  padding: 2rem 0;
  text-align: center;
  color: #666;
  backdrop-filter: blur(10px);
  background: rgba(5, 10, 20, 0.8);
  border-top: 1px solid rgba(0, 255, 136, 0.1);
}

/* Animations */
@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

/* Responsive Design */
@media (max-width: 768px) {
  .page-title {
    font-size: 2rem;
  }

  .stats-overview {
    grid-template-columns: 1fr;
  }

  .section-header {
    flex-direction: column;
    gap: 1rem;
    align-items: stretch;
  }

  .refresh-btn {
    justify-content: center;
  }

  .leaderboard-section {
    padding: 1rem;
  }

  .leaderboard-table {
    font-size: 0.85rem;
  }

  .leaderboard-table thead th,
  .leaderboard-table tbody td {
    padding: 0.75rem 0.5rem;
  }

  .user-stats-grid {
    grid-template-columns: 1fr;
  }

  .user-header {
    flex-direction: column;
    text-align: center;
    align-items: center;
  }
}

@media (max-width: 480px) {
  .leaderboard-table-container {
    font-size: 0.8rem;
  }

  .leaderboard-table thead th,
  .leaderboard-table tbody td {
    padding: 0.5rem 0.25rem;
  }

  .player-cell {
    min-width: 120px;
  }
}
</style>