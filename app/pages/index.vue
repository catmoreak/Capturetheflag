
<template>
  <div class="hacker-theme">
    <canvas ref="threeCanvas" class="three-canvas"></canvas>
    <div ref="contentOverlay" class="content-overlay">
      <header class="main-header">
        <div class="container">
          <div class="logo">CTF_Platform</div>
          <nav>
            <NuxtLink to="/">Home</NuxtLink>
            <NuxtLink to="/challenges">Challenges</NuxtLink>
            <!-- <NuxtLink to="/leaderboard">Leaderboard</NuxtLink> -->
            <!-- <NuxtLink to="/login" class="btn btn-outline">Login</NuxtLink> -->
          </nav>
        </div>
      </header>

      <main>
        <section class="hero">
          <div class="container">
            <h1>Welcome, Agent.</h1>
            <p class="subtitle">The mission is simple. The execution is not. Prove your skill.</p>
            <button @click="goToChallenges" class="btn btn-primary">[ Begin Mission ]</button>
          </div>
        </section>

        <section class="features">
          <div class="container">
            <div class="feature-card" ref="featureCard1">
              <h3>Diverse Challenges</h3>
              <p>From web and mobile to reverse engineering and cryptography.</p>
            </div>
            <!-- <div class="feature-card" ref="featureCard2">
              <h3>Live Leaderboard</h3>
              <p>Track your progress and see how you stack up against the competition in real-time.</p>
            </div> -->
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

const goToChallenges = () => {
  navigateTo('/challenges')
}

const threeCanvas = ref<HTMLCanvasElement | null>(null)
const contentOverlay = ref<HTMLElement | null>(null)
const featureCard1 = ref<HTMLElement | null>(null)
const featureCard2 = ref<HTMLElement | null>(null)
const featureCard3 = ref<HTMLElement | null>(null)

let renderer: THREE.WebGLRenderer
let scene: THREE.Scene
let camera: THREE.PerspectiveCamera
let composer: EffectComposer
const clock = new THREE.Clock()
const mouse = new THREE.Vector2()
const lookAtTarget = new THREE.Vector3()
let cursorLight: THREE.PointLight;
let raycaster: THREE.Raycaster;
let mousePlane: THREE.Mesh;

const packets: any[] = [];
const cardStates: any[] = [];
const collisionEffects: any[] = [];
let cursorParticles: THREE.Points;
let cursorParticleSystem: any[] = [];
const GRID_SIZE = 400;

onMounted(() => {
  if (!threeCanvas.value) return

  
  scene = new THREE.Scene()
  scene.fog = new THREE.Fog(0x050a14, 150, 350);
  camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 0.1, 1000)
  camera.position.set(0, 60, 130)
  renderer = new THREE.WebGLRenderer({ canvas: threeCanvas.value, antialias: true })
  renderer.setSize(window.innerWidth, window.innerHeight)
  renderer.setClearColor(0x050a14, 1)
  renderer.toneMapping = THREE.ReinhardToneMapping;
  scene.add(new THREE.AmbientLight(0x404040, 0.5));

  
  cursorLight = new THREE.PointLight(0x00ff00, 15, 80, 2);
  scene.add(cursorLight);
  raycaster = new THREE.Raycaster();
  mousePlane = new THREE.Mesh(
      new THREE.PlaneGeometry(GRID_SIZE, GRID_SIZE),
      new THREE.MeshBasicMaterial({visible: false})
  );
  mousePlane.rotation.x = -Math.PI / 2;
  scene.add(mousePlane);

  
  setupCursorParticles();

  
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

  
  for (let i=0; i<10; i++) {
      const effect = createCollisionEffect();
      collisionEffects.push(effect);
      scene.add(effect.redFire, effect.yellowFire, effect.whiteSmoke);
  }

  
  const cardElements = [featureCard1.value, featureCard2.value, featureCard3.value];
  cardElements.forEach(el => {
    if(el) setupOrbitalStrike(el);
  });

  
  const renderScene = new RenderPass(scene, camera);
  const bloomPass = new UnrealBloomPass(new THREE.Vector2(window.innerWidth, window.innerHeight), 2.5, 1.0, 0.85);
  composer = new EffectComposer(renderer);
  composer.addPass(renderScene);
  composer.addPass(bloomPass);

  
  window.addEventListener('resize', onWindowResize)
  window.addEventListener('mousemove', onMouseMove)
  contentOverlay.value?.addEventListener('scroll', handleScroll);

  animate()
  handleScroll();
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
        const v = new THREE.Vector3(
            (Math.random() - 0.5) * speed,
            Math.random() * speed * 1.5, // More upward velocity
            (Math.random() - 0.5) * speed
        );
        velocities.set([v.x, v.y, v.z], i * 3);
    }
    geom.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geom.setAttribute('velocity', new THREE.BufferAttribute(velocities, 3));
    const mat = new THREE.PointsMaterial({ 
        color, 
        size, 
        blending: THREE.AdditiveBlending, 
        transparent: true, 
        opacity: 1.0, 
        sizeAttenuation: true 
    });
    const points = new THREE.Points(geom, mat);
    points.visible = false;
    return points;
}

function createCollisionEffect() {
    const redFire = createParticleSystem(0xff4500, 500, 2, 8);
    const yellowFire = createParticleSystem(0xffa500, 500, 2.5, 10);
    const whiteSmoke = createParticleSystem(0xffffff, 800, 2.5, 5);
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

function setupCursorParticles() {
    const PARTICLE_COUNT = 300;
    const geom = new THREE.BufferGeometry();
    const positions = new Float32Array(PARTICLE_COUNT * 3);
    const colors = new Float32Array(PARTICLE_COUNT * 3);
    const sizes = new Float32Array(PARTICLE_COUNT);

    for(let i=0; i < PARTICLE_COUNT; i++) {
        cursorParticleSystem.push({ life: 0, velocity: new THREE.Vector3() });
    }

    geom.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geom.setAttribute('color', new THREE.BufferAttribute(colors, 3));
    geom.setAttribute('size', new THREE.BufferAttribute(sizes, 1));

    const mat = new THREE.PointsMaterial({ size: 0.8, blending: THREE.AdditiveBlending, transparent: true, vertexColors: true });
    cursorParticles = new THREE.Points(geom, mat);
    scene.add(cursorParticles);
}   

function updateCursorParticles(delta: number, emitterPos: THREE.Vector3) {
    const positions = cursorParticles.geometry.getAttribute('position').array as Float32Array;
    const colors = cursorParticles.geometry.getAttribute('color').array as Float32Array;
    const sizes = cursorParticles.geometry.getAttribute('size').array as Float32Array;

    let particlesToSpawn = 3;

    for (let i = 0; i < cursorParticleSystem.length; i++) {
        const p = cursorParticleSystem[i];
        if (p.life > 0) {
            p.life -= delta;
            if (p.life <= 0) {
                sizes[i] = 0;
            } else {
                p.velocity.y -= 0.1 * delta; // gravity
                positions[i*3] += p.velocity.x * delta;
                positions[i*3+1] += p.velocity.y * delta;
                positions[i*3+2] += p.velocity.z * delta;
                sizes[i] = p.life / 1.0 * 1.5; // Fade size
            }
        } else if (particlesToSpawn > 0) {
            p.life = 1.0; // 1 second life
            p.velocity.set((Math.random()-0.5)*2, Math.random()*2, (Math.random()-0.5)*2);
            positions[i*3] = emitterPos.x;
            positions[i*3+1] = emitterPos.y;
            positions[i*3+2] = emitterPos.z;
            
            const color = Math.random() > 0.5 ? new THREE.Color(0xff0000) : new THREE.Color(0xffff00);
            colors[i*3] = color.r;
            colors[i*3+1] = color.g;
            colors[i*3+2] = color.b;

            particlesToSpawn--;
        }
    }
    (cursorParticles.geometry.getAttribute('position') as THREE.BufferAttribute).needsUpdate = true;
    (cursorParticles.geometry.getAttribute('color') as THREE.BufferAttribute).needsUpdate = true;
    (cursorParticles.geometry.getAttribute('size') as THREE.BufferAttribute).needsUpdate = true;
}

 
function setupOrbitalStrike(el: HTMLElement) {
    const worldPos = get3DPositionForElement(el);
    const explosion = createParticleSystem(0xffffff, 200, 0.8, 5);
    explosion.position.copy(worldPos);
    scene.add(explosion);

    cardStates.push({ el, status: 'idle', explosion, progress: 0 });
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
            state.status = 'exploding';
            state.explosion.visible = true;
            state.explosion.userData.life = 0;
            const posAttr = state.explosion.geometry.getAttribute('position');
            for(let i=0; i<posAttr.count; i++) posAttr.setXYZ(i, 0, 0, 0);
            posAttr.needsUpdate = true;
            state.progress = 0;
        }
    });
}

 
const animate = () => {
  requestAnimationFrame(animate)
  const delta = clock.getDelta();
  const time = clock.getElapsedTime();

  
  packets.forEach(p => {
    p.position.z += p.userData.velocity * 60 * delta;
    if (p.userData.velocity > 0 && p.position.z > GRID_SIZE / 2) p.position.z = -GRID_SIZE / 2;
    if (p.userData.velocity < 0 && p.position.z < -GRID_SIZE / 2) p.position.z = GRID_SIZE / 2;
  });

  
  if (Math.random() < 0.001) { // 1 in 50 frames
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

  
  cardStates.forEach(state => {
      if (state.status === 'exploding') {
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

  
  camera.position.x = Math.sin(time * 0.1) * 90;
  camera.position.z = 130 + Math.cos(time * 0.12) * 60;
  camera.position.y = 50 + Math.sin(time * 0.2) * 15;

  
  raycaster.setFromCamera(mouse, camera);
  const intersects = raycaster.intersectObject(mousePlane);
  if (intersects.length > 0) {
      const intersectPoint = intersects[0].point;
      cursorLight.position.copy(intersectPoint);
      cursorLight.position.y = 10;
      updateCursorParticles(delta, intersectPoint);
  }

  lookAtTarget.x = (mouse.x * 40);
  lookAtTarget.y = 20 + (-mouse.y * 20);
  lookAtTarget.z = 0;
  camera.lookAt(lookAtTarget);

  composer.render();
}

 
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
  cursor: none;
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
  transform: translateY(20px);
  transition: opacity 0.5s ease-in-out, transform 0.5s ease-in-out;
  backdrop-filter: blur(10px);
}

.feature-card.is-visible {
  opacity: 1;
  transform: translateY(0);
}

.feature-card h3 {
  font-family: 'Share Tech Mono', monospace;
  font-size: 1.5rem;
  margin-bottom: 1rem;
  color: var(--primary-color);
}

 
.main-footer {
  text-align: center;
  padding: 2rem 0;
  background-color: transparent;
  color: var(--dark-text);
}
</style>

<style>
body, * {
  cursor: auto !important;
}
</style>
