<template>
  <div class="challenges-page">
    <h1>Challenges</h1>
    <p>Welcome to the CTF Challenges! Select a challenge to begin.</p>
    <!-- Challenge list will go here -->
  </div>
</template>

<script setup lang="ts">
// Add logic for fetching and displaying challenges here in the future
</script>

<style scoped>
.challenges-page {
  max-width: 800px;
  margin: 2rem auto;
  padding: 2rem;
  background: var(--card-bg, #181c20);
  border-radius: 10px;
  box-shadow: 0 2px 16px rgba(0,0,0,0.15);
  color: var(--light-text, #fff);
}
.challenges-page h1 {
  font-size: 2.5rem;
  margin-bottom: 1rem;
  color: var(--primary-color, #00ffae);
}
.challenges-page p {
  font-size: 1.2rem;
  margin-bottom: 2rem;
}
</style>
