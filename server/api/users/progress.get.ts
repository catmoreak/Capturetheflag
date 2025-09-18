import { prisma } from '../../../lib/prisma'

export default defineEventHandler(async (event) => {
  try {
    const query = getQuery(event)
    const userId = query.userId as string
    
    if (!userId) {
      throw createError({
        statusCode: 400,
        statusMessage: 'User ID is required'
      })
    }

    const completions = await prisma.challengeCompletion.findMany({
      where: {
        userId: userId
      },
      select: {
        challengeId: true,
        points: true,
        completionTime: true,
        completedAt: true
      },
      orderBy: {
        completedAt: 'asc'
      }
    })

    return {
      success: true,
      completions: completions
    }

  } catch (error) {
    console.error('Error fetching user progress:', error)
    throw createError({
      statusCode: 500,
      statusMessage: 'Failed to fetch user progress'
    })
  }
})