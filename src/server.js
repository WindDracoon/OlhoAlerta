import fastify from "fastify";
import z from 'zod'
import pgk from "bcryptjs"
import {prisma} from './lib/prisma.js'
import jwt from '@fastify/jwt'
import {env} from "./env/index.js";

const {compare, hash} = pgk

const app = fastify()

app.register(jwt, {
    secret: env.JWT_SECRET
})

app.post('/users', async (request, reply) => {
    const registerBodySchema = z.object({
        name: z.string(),
        email: z.string(),
        password: z.string().min(6)
    })
    // Dados que precisam ser colocados no body
    const {name, email, password} = registerBodySchema.parse(request.body)
    
    // Criptografar senha
    const password_hash = await hash(password, 6)
    
    // Verificar se o e-mail existe no banco de dados
    const userWithSameEmail = await prisma.users.findUnique({
        where:{
            email
        }
    })
    
    // Se existir mostrar um error
    if(userWithSameEmail){
        return reply.status(409).send({message:'E-mail já existe'})
    }
    
    // Criar cadastro no banco de dados
    await prisma.users.create({
        data:{
            name,
            email,
            password_hash
        }
    })
    return reply.status(201).send()
})

app.post('/authenticate', async (request, reply) => {
    try{
        const registerBodySchema = z.object({
            email: z.string(),
            password: z.string().min(6)
        })

        const {email, password} = registerBodySchema.parse(request.body)

        const user = await prisma.users.findUnique({
            where:{
                email: email
            }
        })

        if(!user){
            return reply.status(409).send({message:'E-mail não existe'})
        }

        const doesPasswordMatches = await compare(password, user.password_hash)

        if(!doesPasswordMatches){
            return reply.status(409).send({message:'Credenciais inválidas'})
        }

        const token = await reply.jwtSign({}, {
            sign:{
                sub: user.id
            }
        })

        return reply.status(200).send({token})

    }catch{
        return reply.status(500).send({message:'Erro no servidor'})
    }
})

app.listen({
    host:'0.0.0.0',
    port:3333
}).then(() => {
    console.log('💻Servidor rodando na porta 3333💻');
})