import { prisma } from '../../../lib/prisma'

export default defineEventHandler(async (event) => {
  try {

    const leaderboard = await prisma.user.findMany({
      include: {
        completions: {
          select: {
            points: true,
            completionTime: true,
            challengeId: true,
            completedAt: true
          }
        }
      }
    })


    const rankings = leaderboard.map((user: any) => {
      const totalPoints = user.completions.reduce((sum: number, completion: any) => sum + completion.points, 0)
      
      // Count unique challenges by getting unique challenge IDs
      const uniqueChallengeIds = new Set(user.completions.map((c: any) => c.challengeId))
      const solvedChallenges = uniqueChallengeIds.size
      const totalChallenges = 6 // Total number of challenges available
      
      // Debug logging
      if (user.name === 'helloboss' || user.name === 'hacker_shreu') {
        console.log(`Debug for ${user.name}:`, {
          completions: user.completions.length,
          solvedChallenges,
          totalChallenges,
          challengeIds: Array.from(uniqueChallengeIds),
          totalPoints
        })
      }
      
      const averageTime = solvedChallenges > 0 
        ? user.completions.reduce((sum: number, completion: any) => sum + completion.completionTime, 0) / solvedChallenges
        : 0
      const totalTime = user.completions.reduce((sum: number, completion: any) => sum + completion.completionTime, 0)
      
      return {
        id: user.id,
        name: user.name,
        totalPoints,
        solvedChallenges,
        totalChallenges,
        totalTime,
        averageTime: Math.round(averageTime),
        joinedAt: user.createdAt,
        lastActivity: user.completions.length > 0 
          ? Math.max(...user.completions.map((c: any) => new Date(c.completedAt).getTime()))
          : new Date(user.createdAt).getTime()
      }
    })


    rankings.sort((a: any, b: any) => {
      if (b.totalPoints !== a.totalPoints) {
        return b.totalPoints - a.totalPoints
      }
      return a.totalTime - b.totalTime
    })

    
    const rankedLeaderboard = rankings.map((user: any, index: number) => ({
      ...user,
      rank: index + 1
    }))

    return {
      success: true,
      leaderboard: rankedLeaderboard,
      totalUsers: rankedLeaderboard.length
    }

  } catch (error) {
    console.error('Error fetching leaderboard:', error)
    throw createError({
      statusCode: 500,
      statusMessage: 'Failed to fetch leaderboard'
    })
  }
})