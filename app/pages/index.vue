
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
            <NuxtLink to="/leaderboard">Leaderboard</NuxtLink>
            
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
          <div class="footer-content">
            <div class="footer-section">
              <h4>CTF Platform</h4>
              <p>Challenge yourself with the ultimate Capture The Flag experience.</p>
            </div>
            <div class="footer-section">
              <h4>Quick Links</h4>
              <ul>
                <li><NuxtLink to="/">Home</NuxtLink></li>
                <li><NuxtLink to="/challenges">Challenges</NuxtLink></li>
                <li><NuxtLink to="/leaderboard">Leaderboard</NuxtLink></li>
              </ul>
            </div>
            <div class="footer-section">
              <h4>Contact</h4>
              <p>Email: info@ctfplatform.com</p>
              <p>Follow us on social media</p>
              <div class="social-icons">
                <a href="#" aria-label="GitHub">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 0C5.374 0 0 5.373 0 12 0 17.302 3.438 21.8 8.207 23.387c.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0112 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/>
                  </svg>
                </a>
                <a href="#" aria-label="Twitter">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M23.953 4.57a10 10 0 01-2.825.775 4.958 4.958 0 002.163-2.723c-.951.555-2.005.959-3.127 1.184a4.92 4.92 0 00-8.384 4.482C7.69 8.095 4.067 6.13 1.64 3.162a4.822 4.822 0 00-.666 2.475c0 1.71.87 3.213 2.188 4.096a4.904 4.904 0 01-2.228-.616v.06a4.923 4.923 0 003.946 4.827 4.996 4.996 0 01-2.212.085 4.936 4.936 0 004.604 3.417 9.867 9.867 0 01-6.102 2.105c-.39 0-.779-.023-1.17-.067a13.995 13.995 0 007.557 2.209c9.053 0 13.998-7.496 13.998-13.985 0-.21 0-.42-.015-.63A9.935 9.935 0 0024 4.59z"/>
                  </svg>
                </a>
                <a href="#" aria-label="Discord">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M20.317 4.3698a19.7913 19.7913 0 00-4.8851-1.5152.0741.0741 0 00-.0785.0371c-.211.3753-.4447.8648-.6083 1.2495-1.8447-.2762-3.68-.2762-5.4868 0-.1636-.3933-.4058-.8742-.6177-1.2495a.077.077 0 00-.0785-.037 19.7363 19.7363 0 00-4.8852 1.515.0699.0699 0 00-.0321.0277C.5334 9.0458-.319 13.5799.0992 18.0578a.0824.0824 0 00.0312.0561c2.0528 1.5076 4.0413 2.4228 5.9929 3.0294a.0777.0777 0 00.0842-.0276c.4616-.6304.8731-1.2952 1.226-1.9942a.076.076 0 00-.0416-.1057c-.6528-.2476-1.2743-.5495-1.8722-.8923a.077.077 0 01-.0076-.1277c.1258-.0943.2517-.1923.3718-.2914a.0743.0743 0 01.0776-.0105c3.9278 1.7933 8.18 1.7933 12.0614 0a.0739.0739 0 01.0785.0095c.1202.099.246.1981.3728.2924a.077.077 0 01-.0066.1276 12.2986 12.2986 0 01-1.873.8914.0766.0766 0 00-.0407.1067c.3604.698.7719 1.3628 1.225 1.9932a.076.076 0 00.0842.0286c1.961-.6067 3.9495-1.5219 6.0023-3.0294a.077.077 0 00.0313-.0552c.5004-5.177-.8382-9.6739-3.5485-13.6604a.061.061 0 00-.0312-.0286zM8.02 15.3312c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9555-2.4189 2.157-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419-.0189 1.3332-.9555 2.4189-2.1569 2.4189zm7.9748 0c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9554-2.4189 2.1569-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.946 2.4189-2.1568 2.4189Z"/>
                  </svg>
                </a>
                <a href="#" aria-label="LinkedIn">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
                  </svg>
                </a>
                <a href="#" aria-label="Instagram">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zm0-2.163c-3.259 0-3.667.014-4.947.072-4.358.2-6.78 2.618-6.98 6.98-.059 1.281-.073 1.689-.073 4.948 0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98 1.281.058 1.689.072 4.948.072 3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98-1.281-.059-1.69-.073-4.949-.073zm0 5.838c-3.403 0-6.162 2.759-6.162 6.162s2.759 6.163 6.162 6.163 6.162-2.759 6.162-6.163c0-3.403-2.759-6.162-6.162-6.162zm0 10.162c-2.209 0-4-1.79-4-4 0-2.209 1.791-4 4-4s4 1.791 4 4c0 2.21-1.791 4-4 4zm6.406-11.845c-.796 0-1.441.645-1.441 1.44s.645 1.44 1.441 1.44c.795 0 1.439-.645 1.439-1.44s-.644-1.44-1.439-1.44z"/>
                  </svg>
                </a>
                <a href="#" aria-label="YouTube">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M23.498 6.186a3.016 3.016 0 0 0-2.122-2.136C19.505 3.545 12 3.545 12 3.545s-7.505 0-9.377.505A3.017 3.017 0 0 0 .502 6.186C0 8.07 0 12 0 12s0 3.93.502 5.814a3.016 3.016 0 0 0 2.122 2.136c1.871.505 9.376.505 9.376.505s7.505 0 9.377-.505a3.015 3.015 0 0 0 2.122-2.136C24 15.93 24 12 24 12s0-3.93-.502-5.814zM9.545 15.568V8.432L15.818 12l-6.273 3.568z"/>
                  </svg>
                </a>
              </div>
            </div>
          </div>
          <div class="footer-bottom">
            <p>&copy; 2025 CTF Platform. All Rights Reserved.</p>
          </div>
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

interface Particle {
  life: number;
  velocity: THREE.Vector3;
}

class CursorParticle implements Particle {
  life: number;
  velocity!: THREE.Vector3;

  constructor() {
    this.life = 0;
    this.velocity = new THREE.Vector3();
  }
}

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
let cursorParticleSystem: CursorParticle[] = [];
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
        cursorParticleSystem.push(new CursorParticle());
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
        const p = cursorParticleSystem[i]!;
        if (p.life > 0) {
            p.life -= delta;
            if (p.life <= 0) {
                sizes[i] = 0;
            } else {
                if (p.velocity) {
                    p.velocity.y -= 0.1 * delta; // gravity
                }
                const vx = p.velocity ? p.velocity.x : 0;
                const vy = p.velocity ? p.velocity.y : 0;
                const vz = p.velocity ? p.velocity.z : 0;
                // @ts-ignore
                positions[i*3] += vx * delta;
                // @ts-ignore
                positions[i*3+1] += vy * delta;
                // @ts-ignore
                positions[i*3+2] += vz * delta;
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
      const intersectPoint = intersects[0]!.point;
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
  transition: all 0.4s ease-in-out;
  backdrop-filter: blur(10px);
  position: relative;
  overflow: hidden;
}

.feature-card::before {
  content: '';
  position: absolute;
  top: 0;
  left: -100%;
  width: 100%;
  height: 100%;
  background: linear-gradient(90deg, transparent, rgba(0, 255, 136, 0.1), transparent);
  transition: left 0.6s ease-in-out;
}

.feature-card:hover {
  transform: translateY(-8px) scale(1.02);
  border-color: var(--primary-color);
  box-shadow: 
    0 0 20px rgba(0, 255, 136, 0.3),
    0 8px 32px rgba(0, 255, 136, 0.1),
    inset 0 0 0 1px rgba(0, 255, 136, 0.2);
  background-color: rgba(16, 24, 38, 0.95);
}

.feature-card:hover::before {
  left: 100%;
}

.feature-card:hover h3 {
  text-shadow: 0 0 10px var(--primary-color);
  color: #00ffaa;
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
  background: linear-gradient(135deg, rgba(0, 0, 0, 0.9), rgba(16, 24, 38, 0.9));
  color: #ffffff;
  padding: 3rem 0 1rem;
  border-top: 1px solid var(--border-color);
  backdrop-filter: blur(10px);
  position: relative;
  box-shadow: 0 -4px 20px rgba(0, 255, 136, 0.2);
}

.footer-content {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 2rem;
  margin-bottom: 2rem;
}

.footer-section h4 {
  color: var(--primary-color);
  margin-bottom: 1rem;
  font-size: 1.2rem;
  text-transform: uppercase;
  letter-spacing: 1px;
}

.footer-section p {
  color: #cccccc;
  line-height: 1.6;
  margin: 0.5rem 0;
}

.footer-section ul {
  list-style: none;
  padding: 0;
}

.footer-section ul li {
  margin: 0.5rem 0;
}

.footer-section ul li a {
  color: #cccccc;
  text-decoration: none;
  transition: color 0.3s ease;
}

.footer-section ul li a:hover {
  color: var(--primary-color);
  text-shadow: 0 0 5px var(--primary-color);
}

.footer-bottom {
  border-top: 1px solid rgba(255, 255, 255, 0.1);
  padding-top: 1rem;
  text-align: center;
}

.footer-bottom p {
  color: #888888;
  font-size: 0.9rem;
  margin: 0;
}

.social-icons {
  display: flex;
  gap: 1rem;
  margin-top: 1rem;
}

.social-icons a {
  color: #cccccc;
  transition: color 0.3s ease, transform 0.3s ease;
  display: inline-block;
}

.social-icons a:hover {
  color: var(--primary-color);
  transform: scale(1.1);
}
</style>

<style>
body, * {
  cursor: auto !important;
}
</style>
