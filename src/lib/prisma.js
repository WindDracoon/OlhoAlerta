import {PrismaClient} from '@prisma/client'
import {env} from '../env/index.js'

const _prisma = new PrismaClient({
    log: env.NODE_ENV === 'dev' ? ['query'] : []
})

export const prisma = _prisma