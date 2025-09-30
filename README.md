# Capture the Flag (CTF) Platform

A modern, cyberpunk-themed Capture the Flag platform built with Nuxt.js, featuring interactive challenges, real-time leaderboards, and comprehensive progress tracking.

## 🚀 Features

- **Cyberpunk UI**: Immersive 3D background with Three.js and futuristic design
- **Challenge System**: 8 diverse CTF challenges including web exploitation, steganography, forensics, and cryptography
- **User Management**: Registration system with unique callsigns
- **Progress Tracking**: Real-time completion tracking with points and timing
- **Leaderboard**: Dynamic ranking system for competitive play
- **Admin Panel**: Administrative controls for managing users and completions
- **Responsive Design**: Optimized for desktop and mobile devices

## 🛠️ Tech Stack

- **Frontend**: Nuxt.js 4, Vue 3, TypeScript
- **3D Graphics**: Three.js
- **Backend**: Nuxt Server API
- **Database**: PostgreSQL with Prisma ORM
- **Styling**: Custom CSS with cyberpunk theme
- **Build Tool**: Vite

## 📋 Prerequisites

- Node.js 18+
- PostgreSQL database
- npm or yarn package manager

## 🚀 Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/catmoreak/Capturetheflag.git
   cd Capturetheflag
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Database Setup**
   - Create a PostgreSQL database
   - Copy `.env.example` to `.env` and configure your database URL:
     ```
     DATABASE_URL="postgresql://username:password@localhost:5432/ctf_db"
     ```

4. **Initialize Database**
   ```bash
   npx prisma generate
   npx prisma db push
   ```

5. **Start Development Server**
   ```bash
   npm run dev
   ```

   The application will be available at `http://localhost:3000`

## 📁 Project Structure

```
├── app/
│   ├── pages/           # Vue pages (challenges, leaderboard, index)
│   └── components/      # Reusable Vue components
├── server/
│   └── api/            # Server API endpoints
│       ├── challenges/ # Challenge completion endpoints
│       ├── leaderboard/# Leaderboard data
│       ├── users/      # User registration and progress
│       └── admin/      # Administrative functions
├── prisma/
│   └── schema.prisma   # Database schema
├── lib/
│   └── prisma.ts       # Prisma client configuration
├── types/              # TypeScript type definitions
└── public/             # Static assets
```

## 🎯 Challenges

The platform includes 8 CTF challenges:

1. **BASIC_RECON** - Web reconnaissance basics
2. **CAESAR_DECRYPT** - Classical cryptography
3. **WEB_EXPLOIT** - Web security exploitation
4. **STEGANOGRAPHY** - Hidden data extraction
5. **JS_OBFUSCATION** - JavaScript reverse engineering
6. **FORENSICS_ANALYSIS** - Digital forensics
7. **REVERSE_ENGINEERING** - Binary reversing and analysis challenges
8. **NETWORK_PWN** - Network/service exploitation and pwn-style tasks

## 🔧 API Endpoints

### User Management
- `POST /api/users/register` - Register new user
- `GET /api/users/progress` - Get user progress

### Challenges
- `POST /api/challenges/complete` - Submit challenge completion

### Leaderboard
- `GET /api/leaderboard` - Get leaderboard data

### Admin
- `GET /api/admin/users/[id]` - User management
- `GET /api/admin/completions/[id]` - Completion management

## 🗄️ Database Schema

### User
- `id`: Unique identifier
- `name`: Unique callsign
- `createdAt/updatedAt`: Timestamps

### ChallengeCompletion
- `id`: Unique identifier
- `userId`: Reference to user
- `challengeId`: Challenge number (1-6)
- `points`: Points earned
- `completionTime`: Time taken (seconds)
- `completedAt`: Completion timestamp

## 🚀 Production Build

1. **Build the application**
   ```bash
   npm run build
   ```

2. **Preview production build**
   ```bash
   npm run preview
   ```

## 📊 Development

### Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run preview` - Preview production build
- `npm run generate` - Generate static site

### Database Commands

- `npx prisma studio` - Open Prisma Studio
- `npx prisma db push` - Push schema changes to database
- `npx prisma generate` - Generate Prisma client

## 🎨 Customization

### Themes
The application uses a cyberpunk color scheme. Colors can be modified in the CSS variables within component files.

### Challenges
Add new challenges by:
1. Updating the challenge list in the frontend
2. Adding corresponding API logic
3. Updating the database schema if needed

### Scoring
Points and timing calculations can be adjusted in the challenge completion API endpoint.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License 
## 🙏 Acknowledgments

- Built with [Nuxt.js](https://nuxt.com/)
- 3D graphics powered by [Three.js](https://threejs.org/)
- Database managed with [Prisma](https://prisma.io/)
