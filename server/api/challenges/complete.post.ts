import { prisma } from '../../../lib/prisma'

export default defineEventHandler(async (event) => {
  if (event.node.req.method !== 'POST') {
    throw createError({
      statusCode: 405,
      statusMessage: 'Method Not Allowed'
    })
  }

  try {
    const { userId, challengeId, points, completionTime } = await readBody(event)
    
    if (!userId || challengeId == null || !points || !completionTime) {
      throw createError({
        statusCode: 400,
        statusMessage: 'Missing required fields'
      })
    }


    const existingCompletion = await prisma.challengeCompletion.findUnique({
      where: {
        userId_challengeId: {
          userId,
          challengeId: parseInt(challengeId)
        }
      }
    })

    if (existingCompletion) {
      return {
        success: true,
        completion: existingCompletion,
        message: 'Challenge already completed!'
      }
    }

    const completion = await prisma.challengeCompletion.create({
      data: {
        userId,
        challengeId: parseInt(challengeId),
        points: parseInt(points),
        completionTime: parseInt(completionTime)
      }
    })

    return {
      success: true,
      completion,
      message: 'Challenge completed successfully!'
    }

  } catch (error) {
    console.error('Error completing challenge:', error)
    throw createError({
      statusCode: 500,
      statusMessage: 'Failed to complete challenge'
    })
  }
})