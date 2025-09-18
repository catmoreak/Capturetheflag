import { prisma } from '../../../lib/prisma'

export default defineEventHandler(async (event) => {
  if (event.node.req.method !== 'POST') {
    throw createError({
      statusCode: 405,
      statusMessage: 'Method Not Allowed'
    })
  }

  try {
    const { name } = await readBody(event)
    
    if (!name || name.trim().length < 2) {
      throw createError({
        statusCode: 400,
        statusMessage: 'Name must be at least 2 characters long'
      })
    }

    
    const existingUser = await prisma.user.findUnique({
      where: { name: name.trim() }
    })

    if (existingUser) {
      return {
        success: true,
        user: existingUser,
        message: 'Welcome back!'
      }
    }

   
    const user = await prisma.user.create({
      data: {
        name: name.trim()
      }
    })

    return {
      success: true,
      user,
      message: 'User created successfully!'
    }

  } catch (error) {
    console.error('Error creating/finding user:', error)
    throw createError({
      statusCode: 500,
      statusMessage: 'Failed to create user'
    })
  }
})