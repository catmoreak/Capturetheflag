import { prisma } from '../../../lib/prisma'

export default defineEventHandler(async (event) => {
  try {
    const query = getQuery(event)
    const adminKey = query.adminKey as string


    if (adminKey !== 'administrator123') {
      throw createError({
        statusCode: 403,
        statusMessage: 'Access denied. Invalid admin key.'
      })
    }

    const users = await prisma.user.findMany({
      include: {
        completions: {
          select: {
            challengeId: true,
            points: true,
            completionTime: true,
            completedAt: true
          }
        }
      },
      orderBy: {
        createdAt: 'desc'
      }
    })

    return {
      success: true,
      users: users
    }

  } catch (error) {
    console.error('Error fetching users:', error)
    throw createError({
      statusCode: 500,
      statusMessage: 'Failed to fetch users'
    })
  }
})