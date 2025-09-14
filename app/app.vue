
<template>
  <div class="hacker-theme">
    <canvas ref="threeCanvas" class="three-canvas"></canvas>
    <div ref="contentOverlay" class="content-overlay">
      <header class="main-header">
        <div class="container">
          <div class="logo">CTF_Platform</div>
          <nav>
            <a href="#">Home</a>
            <a href="#">Challenges</a>
            <a href="#">Leaderboard</a>
            <a href="#" class="btn btn-outline">Login</a>
          </nav>
        </div>
      </header>

      <main>
        <section class="hero">
          <div class="container">
            <h1>Welcome, Agent.</h1>
            <p class="subtitle">The mission is simple. The execution is not. Prove your skill.</p>
            <a href="#" class="btn btn-primary">[ Begin Mission ]</a>
          </div>
        </section>

        <section class="features">
          <div class="container">
            <div class="feature-card" ref="featureCard1">
              <h3>Diverse Challenges</h3>
              <p>From web and mobile to reverse engineering and cryptography.</p>
            </div>
            <div class="feature-card" ref="featureCard2">
              <h3>Live Leaderboard</h3>
              <p>Track your progress and see how you stack up against the competition in real-time.</p>
            </div>
            <div class="feature-card" ref="featureCard3">
              <h3>Community & Learning</h3>
              <p>Join a vibrant community and sharpen your skills in a collaborative environment.</p>
            </div>
          </div>
        </section>
      </main>

      <footer class="main-footer">
        <div class="container">
          <p>&copy; 2025 CTF Platform. All Rights Reserved.</p>
        </div>
      </footer>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import * as THREE from 'three'
import { EffectComposer } from 'three/examples/jsm/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/examples/jsm/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'three/examples/jsm/postprocessing/UnrealBloomPass.js';

// --- Refs for DOM elements ---
const threeCanvas = ref<HTMLCanvasElement | null>(null)
const contentOverlay = ref<HTMLElement | null>(null)
const featureCard1 = ref<HTMLElement | null>(null)
const featureCard2 = ref<HTMLElement | null>(null)
const featureCard3 = ref<HTMLElement | null>(null)

// --- 3D Scene variables ---
let renderer: THREE.WebGLRenderer
let scene: THREE.Scene
let camera: THREE.PerspectiveCamera
let composer: EffectComposer
const clock = new THREE.Clock()
const mouse = new THREE.Vector2()
const lookAtTarget = new THREE.Vector3()

// --- Animation variables ---
const packets: any[] = [];
const cardStates: any[] = [];
const collisionEffects: any[] = [];
const GRID_SIZE = 400;

onMounted(() => {
  if (!threeCanvas.value) return

  // --- Basic Scene Setup ---
  scene = new THREE.Scene()
  scene.fog = new THREE.Fog(0x050a14, 150, 350);
  camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 0.1, 1000)
  camera.position.set(0, 60, 130)
  renderer = new THREE.WebGLRenderer({ canvas: threeCanvas.value, antialias: true })
  renderer.setSize(window.innerWidth, window.innerHeight)
  renderer.setClearColor(0x050a14, 1)
  renderer.toneMapping = THREE.ReinhardToneMapping;
  scene.add(new THREE.AmbientLight(0x404040, 0.5));

  // --- Background Grid and Packets ---
  const gridHelper = new THREE.GridHelper(GRID_SIZE, 20, 0x00ff88, 0xff0000);
  (gridHelper.material as THREE.Material).transparent = true;
  (gridHelper.material as THREE.Material).opacity = 0.1;
  scene.add(gridHelper);

  const greenPacketMat = new THREE.MeshStandardMaterial({ color: 0x00ff88, emissive: 0x00ff88, emissiveIntensity: 2 });
  const redPacketMat = new THREE.MeshStandardMaterial({ color: 0xff0000, emissive: 0xff0000, emissiveIntensity: 2 });
  const packetGeom = new THREE.BoxGeometry(1, 1, 5);
  for (let i = 0; i < 100; i++) {
    const isAttacker = i >= 50;
    const mat = isAttacker ? redPacketMat : greenPacketMat;
    const packet = new THREE.Mesh(packetGeom, mat);
    packet.position.set((Math.random() - 0.5) * GRID_SIZE, 0.5, (Math.random() - 0.5) * GRID_SIZE);
    packet.userData.velocity = isAttacker ? (Math.random() * -1 - 0.5) : (Math.random() * 1 + 0.5);
    packets.push(packet);
    scene.add(packet);
  }

  // --- Collision Effects Pool ---
  for (let i=0; i<10; i++) {
      const effect = createCollisionEffect();
      collisionEffects.push(effect);
      scene.add(effect.redFire, effect.yellowFire, effect.whiteSmoke);
  }

  // --- Orbital Strike Animations Setup ---
  const cardElements = [featureCard1.value, featureCard2.value, featureCard3.value];
  cardElements.forEach(el => {
    if(el) setupOrbitalStrike(el);
  });

  // --- Post-processing ---
  const renderScene = new RenderPass(scene, camera);
  const bloomPass = new UnrealBloomPass(new THREE.Vector2(window.innerWidth, window.innerHeight), 1.2, 0.5, 0.85);
  composer = new EffectComposer(renderer);
  composer.addPass(renderScene);
  composer.addPass(bloomPass);

  // --- Event Listeners and Final Setup ---
  window.addEventListener('resize', onWindowResize)
  window.addEventListener('mousemove', onMouseMove)
  contentOverlay.value?.addEventListener('scroll', handleScroll);

  animate()
  handleScroll(); // Initial check
})

onUnmounted(() => {
    window.removeEventListener('resize', onWindowResize);
    window.removeEventListener('mousemove', onMouseMove);
    contentOverlay.value?.removeEventListener('scroll', handleScroll);
});

function createParticleSystem(color: number, count: number, size: number, speed: number) {
    const geom = new THREE.BufferGeometry();
    const positions = new Float32Array(count * 3);
    const velocities = new Float32Array(count * 3);
    for (let i = 0; i < count; i++) {
        positions.set([0,0,0], i * 3);
        const v = new THREE.Vector3().randomDirection().multiplyScalar(Math.random() * speed);
        velocities.set([v.x, v.y, v.z], i * 3);
    }
    geom.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geom.setAttribute('velocity', new THREE.BufferAttribute(velocities, 3));
    const mat = new THREE.PointsMaterial({ color, size, blending: THREE.AdditiveBlending, transparent: true, opacity: 1.0 });
    const points = new THREE.Points(geom, mat);
    points.visible = false;
    return points;
}

function createCollisionEffect() {
    const redFire = createParticleSystem(0xff0000, 100, 0.8, 6);
    const yellowFire = createParticleSystem(0xffff00, 100, 0.7, 4);
    const whiteSmoke = createParticleSystem(0xffffff, 150, 1.0, 2);
    return { redFire, yellowFire, whiteSmoke, life: 0, visible: false };
}

function triggerCollision() {
    const effect = collisionEffects.find(e => !e.visible);
    if (effect) {
        const x = (Math.random() - 0.5) * (GRID_SIZE * 0.8);
        const z = (Math.random() * (GRID_SIZE / 2)); // Front half
        const position = new THREE.Vector3(x, 1, z);

        Object.values(effect).forEach((particleSystem: any) => {
            if (particleSystem instanceof THREE.Points) {
                particleSystem.position.copy(position);
                const posAttr = particleSystem.geometry.getAttribute('position');
                posAttr.needsUpdate = true;
                for(let i=0; i<posAttr.count; i++) {
                    posAttr.setXYZ(i, 0, 0, 0);
                }
                particleSystem.visible = true;
            }
        });
        effect.life = 0;
        effect.visible = true;
    }
}

// --- Card Animation Functions ---
function setupOrbitalStrike(el: HTMLElement) {
    const worldPos = get3DPositionForElement(el);
    const beamMat = new THREE.MeshBasicMaterial({ color: 0xffffff, transparent: true, opacity: 0.8 });
    const beamGeom = new THREE.CylinderGeometry(1, 2, 200, 16);
    const beam = new THREE.Mesh(beamGeom, beamMat);
    beam.position.set(worldPos.x, 100, worldPos.z);
    beam.scale.set(1, 0, 1);
    beam.visible = false;
    scene.add(beam);

    const explosion = createParticleSystem(0xffffff, 200, 0.8, 5);
    explosion.position.copy(worldPos);
    scene.add(explosion);

    cardStates.push({ el, status: 'idle', beam, explosion, progress: 0 });
}

function get3DPositionForElement(el: HTMLElement): THREE.Vector3 {
    const rect = el.getBoundingClientRect();
    const x = rect.left + rect.width / 2;
    const y = rect.top + rect.height / 2;
    const vec = new THREE.Vector3((x / window.innerWidth) * 2 - 1, -(y / window.innerHeight) * 2 + 1, 0.5);
    vec.unproject(camera);
    const dir = vec.sub(camera.position).normalize();
    const distance = (10 - camera.position.y) / dir.y; // Project onto y=10 plane
    return camera.position.clone().add(dir.multiplyScalar(distance));
}

function handleScroll() {
    cardStates.forEach(state => {
        const rect = state.el.getBoundingClientRect();
        if (rect.top < window.innerHeight * 0.75 && state.status === 'idle') {
            state.status = 'beam_incoming';
            state.beam.visible = true;
            state.progress = 0;
        }
    });
}

// --- Main Animation Loop ---
const animate = () => {
  requestAnimationFrame(animate)
  const delta = clock.getDelta();
  const time = clock.getElapsedTime();

  // Animate background packets
  packets.forEach(p => {
    p.position.z += p.userData.velocity * 60 * delta;
    if (p.userData.velocity > 0 && p.position.z > GRID_SIZE / 2) p.position.z = -GRID_SIZE / 2;
    if (p.userData.velocity < 0 && p.position.z < -GRID_SIZE / 2) p.position.z = GRID_SIZE / 2;
  });

  // --- Collision Logic ---
  if (Math.random() < 0.025) { // Approx 1 in 40 frames
      triggerCollision();
  }

  collisionEffects.forEach(e => {
      if (e.visible) {
          e.life += delta;
          ['redFire', 'yellowFire', 'whiteSmoke'].forEach(key => {
              const ps = e[key];
              const posAttr = ps.geometry.getAttribute('position');
              const velAttr = ps.geometry.getAttribute('velocity');
              for (let i = 0; i < posAttr.count; i++) {
                  posAttr.array[i*3] += velAttr.array[i*3] * delta;
                  posAttr.array[i*3+1] += velAttr.array[i*3+1] * delta;
                  posAttr.array[i*3+2] += velAttr.array[i*3+2] * delta;
              }
              posAttr.needsUpdate = true;
              ps.material.opacity = 1.0 - (e.life / 1.5); // 1.5 second life
          });

          if (e.life >= 1.5) e.visible = false;
      }
  });

  // Animate card strikes
  cardStates.forEach(state => {
      if (state.status === 'beam_incoming') {
          state.progress += delta / 0.2;
          state.beam.scale.y = Math.sin(state.progress * Math.PI);
          if (state.progress >= 1) {
              state.status = 'exploding';
              state.beam.visible = false;
              state.explosion.visible = true;
              state.explosion.userData.life = 0;
              const posAttr = state.explosion.geometry.getAttribute('position');
              for(let i=0; i<posAttr.count; i++) posAttr.setXYZ(i, 0, 0, 0);
              posAttr.needsUpdate = true;
              state.progress = 0;
          }
      } else if (state.status === 'exploding') {
          state.progress += delta / 1.0;
          const posAttr = state.explosion.geometry.getAttribute('position');
          const velAttr = state.explosion.geometry.getAttribute('velocity');
          for (let i = 0; i < posAttr.count; i++) {
              posAttr.array[i*3] += velAttr.array[i*3] * delta;
          }
          posAttr.needsUpdate = true;
          state.explosion.material.opacity = 1.0 - state.progress;

          if (state.progress > 0.3) state.el.classList.add('is-visible');
          if (state.progress >= 1) {
              state.status = 'finished';
              state.explosion.visible = false;
          }
      }
  });

  // Animate Camera
  camera.position.x = Math.sin(time * 0.1) * 90;
  camera.position.z = 130 + Math.cos(time * 0.12) * 60;
  camera.position.y = 50 + Math.sin(time * 0.2) * 15;

  // Mouse control
  lookAtTarget.x = (mouse.x * 40);
  lookAtTarget.y = 20 + (-mouse.y * 20);
  lookAtTarget.z = 0;
  camera.lookAt(lookAtTarget);

  composer.render();
}

// --- Event Handlers ---
const onWindowResize = () => {
  const width = window.innerWidth;
  const height = window.innerHeight;
  camera.aspect = width / height;
  camera.updateProjectionMatrix();
  renderer.setSize(width, height);
  composer.setSize(width, height);
}

const onMouseMove = (event: MouseEvent) => {
    mouse.x = (event.clientX / window.innerWidth) * 2 - 1;
    mouse.y = -(event.clientY / window.innerHeight) * 2 + 1;
}

</script>

<style>
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

body {
  background-color: var(--dark-bg);
  color: var(--light-text);
  font-family: 'Roboto', sans-serif;
  margin: 0;
  padding: 0;
  overflow: hidden;
}

.hacker-theme {
  position: relative;
}

.three-canvas {
  position: fixed;
  top: 0;
  left: 0;
  z-index: 1;
}

.content-overlay {
  position: relative;
  z-index: 2;
  height: 100vh;
  overflow-y: auto;
  overflow-x: hidden;
}

.container {
  width: 90%;
  max-width: 1100px;
  margin: 0 auto;
}

/* Header */
.main-header {
  background: transparent;
  padding: 1.5rem 0;
  position: fixed;
  width: 100%;
  z-index: 10;
  background: linear-gradient(to bottom, rgba(5, 10, 20, 0.8), transparent);
}

.main-header .container {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.logo {
  font-family: 'Share Tech Mono', monospace;
  font-size: 1.5rem;
  font-weight: 700;
  color: var(--light-text);
}

nav a {
  font-family: 'Share Tech Mono', monospace;
  color: var(--dark-text);
  text-decoration: none;
  margin-left: 2rem;
  transition: all 0.3s ease;
}

nav a:hover {
  color: var(--primary-color);
  text-shadow: 0 0 5px var(--primary-color);
}

.btn {
  font-family: 'Share Tech Mono', monospace;
  padding: 0.6rem 1.5rem;
  border-radius: 4px;
  text-decoration: none;
  font-weight: 700;
  background-color: transparent;
  border: 1px solid var(--primary-color);
  color: var(--primary-color);
  transition: all 0.3s ease;
}

.btn:hover {
    background-color: var(--primary-color);
    color: var(--dark-bg);
    box-shadow: 0 0 15px var(--primary-color);
}

/* Hero Section */
.hero {
  text-align: center;
  padding: 12rem 0 8rem 0;
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 80vh;
}

.hero h1 {
  font-family: 'Share Tech Mono', monospace;
  font-size: 4rem;
  margin-bottom: 1rem;
  color: var(--light-text);
  font-weight: 700;
}

.hero .subtitle {
  font-size: 1.2rem;
  max-width: 550px;
  margin: 0 auto 2.5rem;
  color: var(--dark-text);
  font-weight: 300;
  line-height: 1.6;
}

/* Features Section */
.features {
  padding: 4rem 0 8rem 0;
}

.features .container {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 2rem;
}

.feature-card {
  background-color: var(--card-bg);
  padding: 2.5rem;
  border: 1px solid var(--border-color);
  border-radius: 8px;
  text-align: center;
  opacity: 0; /* Start hidden */
  transition: opacity 0.3s ease-in-out;
  backdrop-filter: blur(10px);
}

.feature-card.is-visible {
  opacity: 1;
}

.feature-card h3 {
  font-family: 'Share Tech Mono', monospace;
  font-size: 1.5rem;
  margin-bottom: 1rem;
  color: var(--primary-color);
}

/* Footer */
.main-footer {
  text-align: center;
  padding: 2rem 0;
  background-color: transparent;
  color: var(--dark-text);
}
</style>
