<template>
  <div class="admin-green-root">
    <header class="admin-green-header">
      <h1>
        <!-- <svg class="admin-green-icon" viewBox="0 0 24 24" fill="none">
          <circle cx="12" cy="12" r="10" stroke="#00ff99" stroke-width="2" />
          <path d="M12 8v4l3 2" stroke="#00ff99" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
        </svg> -->
        Admin Dashboard
      </h1>
     
    </header>
    <main v-if="isAuthenticated" class="admin-green-main">
      <section class="admin-green-stats">
        <div class="admin-green-stat">
          <span class="stat-label">Total Users</span>
          <span class="stat-value">{{ users.length }}</span>
        </div>
        <div class="admin-green-stat">
          <span class="stat-label">Total Completions</span>
          <span class="stat-value">{{ totalCompletions }}</span>
        </div>
        <div class="admin-green-stat">
          <span class="stat-label">Active Users (7d)</span>
          <span class="stat-value">{{ activeUsers }}</span>
        </div>
      </section>
      <section class="admin-green-table-section">
        <h2>User Directory</h2>
        <table class="admin-green-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>ID</th>
              <th>Joined</th>
              <th>Completions</th>
              <th>Points</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="user in users" :key="user.id">
              <td>{{ user.name }}</td>
              <td class="mono">{{ user.id }}</td>
              <td>{{ formatDate(user.createdAt) }}</td>
              <td>{{ user.completions.length }}</td>
              <td>{{ totalPoints(user) }}</td>
            </tr>
          </tbody>
        </table>
      </section>
    </main>
    <main v-else class="admin-green-auth">
      <form @submit.prevent="authenticate" class="admin-green-auth-form">
        <h2>Admin Access</h2>
        <input v-model="adminKey" type="password" placeholder="Access Key" required />
        <button type="submit">Access Dashboard</button>
        <span v-if="authError" class="admin-green-error">{{ authError }}</span>
      </form>
    </main>
  </div>
</template>

<script setup lang="ts">
interface User {
  id: string
  name: string
  createdAt: string
  completions: Array<{ points: number; completedAt: string }>
}
const adminKey = ref("");
const isAuthenticated = ref(false);
const authError = ref("");
const users = ref<User[]>([])
const authenticate = async () => {
  authError.value = "";
  try {
    const response = await $fetch<any>("/api/admin/users", {
      method: "GET",
      query: { adminKey: adminKey.value },
    });
    if (response.success) {
      isAuthenticated.value = true;
      users.value = response.users;
      adminKey.value = "";
    }
  } catch (err: any) {
    authError.value = err.statusMessage || "Authentication failed";
  }
}
const formatDate = (date: string) => new Date(date).toLocaleDateString()
const totalCompletions = computed(() => users.value.reduce((t, u) => t + u.completions.length, 0))
const activeUsers = computed(() => {
  const sevenDaysAgo = new Date();
  sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
  return users.value.filter(u => {
    if (!u.completions || u.completions.length === 0) return false;
    const lastCompletion = u.completions[u.completions.length-1];
    if (!lastCompletion || !lastCompletion.completedAt) return false;
    return new Date(lastCompletion.completedAt).getTime() > sevenDaysAgo.getTime();
  }).length;
})
const totalPoints = (user: User) => user.completions.reduce((sum, c) => sum + c.points, 0)
</script>

<style scoped>
.admin-green-root {
  min-height: 100vh;
  max-height: 100vh;
  overflow-y: auto;
  background: linear-gradient(135deg, #0a0a0a 0%, #0f291e 60%, #0a0a0a 100%);
  font-family: 'Share Tech Mono', 'Inter', 'Segoe UI', monospace, sans-serif;
  color: #e0fce0;
  display: flex;
  flex-direction: column;
}
.admin-green-header {
  padding: 2rem 0 1rem 0;
  text-align: center;
  background: rgba(10, 10, 10, 0.92);
  border-bottom: 2px solid #00ff99;
  box-shadow: 0 2px 24px #00ff9922;
}
.admin-green-icon {
  width: 2.5rem;
  height: 2.5rem;
  vertical-align: middle;
  margin-right: 0.5rem;
  filter: drop-shadow(0 0 12px #00ff99);
}
.admin-green-header h1 {
  color: #00ff99;
  font-size: 2.2rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  margin: 0;
  display: inline-flex;
  align-items: center;
}
.admin-green-subtitle {
  color: #e0fce0;
  font-size: 1rem;
  letter-spacing: 0.08em;
  display: block;
  margin-top: 0.5rem;
}
.admin-green-main {
  flex: 1;
  padding: 2rem 0;
  max-width: 900px;
  margin: 0 auto;
  width: 100%;
}
.admin-green-stats {
  display: flex;
  gap: 2rem;
  justify-content: center;
  margin-bottom: 2rem;
}
.admin-green-stat {
  background: rgba(15, 41, 30, 0.85);
  border-radius: 16px;
  box-shadow: 0 0 24px #00ff9922;
  border: 2px solid #00ff99;
  padding: 1.5rem 2rem;
  text-align: center;
  min-width: 160px;
}
.stat-label {
  color: #00ff99;
  font-size: 1rem;
  font-weight: 600;
  letter-spacing: 0.08em;
  margin-bottom: 0.5rem;
  display: block;
}
.stat-value {
  color: #e0fce0;
  font-size: 2rem;
  font-weight: 700;
  text-shadow: 0 0 12px #00ff99;
}
.admin-green-table-section {
  background: rgba(15, 41, 30, 0.85);
  border-radius: 16px;
  box-shadow: 0 0 24px #00ff9922;
  border: 2px solid #00ff99;
  padding: 2rem;
  margin-bottom: 2rem;
}
.admin-green-table-section h2 {
  color: #00ff99;
  font-size: 1.2rem;
  font-weight: 700;
  margin-bottom: 1rem;
}
.admin-green-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 1rem;
}
.admin-green-table th, .admin-green-table td {
  padding: 0.75rem 1rem;
  border-bottom: 1px solid #00ff9922;
  text-align: left;
}
.admin-green-table th {
  color: #00ff99;
  font-weight: 700;
  background: rgba(10, 10, 10, 0.92);
  text-shadow: 0 0 8px #00ff99;
}
.admin-green-table td {
  color: #e0fce0;
}
.admin-green-table .mono {
  font-family: 'Share Tech Mono', 'Monaco', monospace;
  color: #00ff99;
}
.admin-green-auth {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgba(10, 10, 10, 0.92);
}
.admin-green-auth-form {
  background: rgba(15, 41, 30, 0.85);
  border-radius: 16px;
  box-shadow: 0 0 24px #00ff9922;
  border: 2px solid #00ff99;
  padding: 2rem 2.5rem;
  text-align: center;
  min-width: 320px;
}
.admin-green-auth-form h2 {
  color: #00ff99;
  font-size: 1.3rem;
  font-weight: 700;
  margin-bottom: 1.5rem;
}
.admin-green-auth-form input {
  width: 100%;
  padding: 0.75rem 1rem;
  border: 2px solid #00ff99;
  border-radius: 8px;
  font-size: 1rem;
  background: #0a0a0a;
  color: #e0fce0;
  margin-bottom: 1rem;
}
.admin-green-auth-form button {
  background: linear-gradient(90deg, #00ff99 0%, #0f0 100%);
  color: #0a0a0a;
  border: none;
  padding: 0.875rem 1.5rem;
  border-radius: 8px;
  font-size: 1rem;
  font-weight: 700;
  cursor: pointer;
  box-shadow: 0 0 12px #00ff99;
  transition: all 0.2s ease;
  text-transform: uppercase;
}
.admin-green-auth-form button:hover {
  background: linear-gradient(90deg, #0f0 0%, #00ff99 100%);
  color: #fff;
  box-shadow: 0 0 24px #00ff99;
}
.admin-green-error {
  color: #ff4f4f;
  font-size: 1rem;
  margin-top: 1rem;
  display: block;
}
</style>