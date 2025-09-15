import express from 'express'
import cors from 'cors'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'
import { supabase } from './supabaseClient.js'

dotenv.config()
const app = express()
app.use(cors())
app.use(express.json())

// middleware para autenticar token
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1]
  if (!token) return res.status(401).json({ error: 'Token ausente' })
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Token inválido' })
    req.user = decoded
    next()
  })
}

// rota de cadastro
app.post('/auth/register', async (req, res) => {
  const { nome, email, senha } = req.body
  const hash = await bcrypt.hash(senha, 10)

  const { data, error } = await supabase
    .from('users')
    .insert([{ nome, email, senha: hash }])

  if (error) return res.status(400).json({ error: error.message })
  res.json({ message: 'Usuário criado com sucesso', data })
})

// rota de login
app.post('/auth/login', async (req, res) => {
  const { email, senha } = req.body

  const { data: users, error } = await supabase
    .from('users')
    .select('*')
    .eq('email', email)
    .single()

  if (error || !users) return res.status(400).json({ error: 'Usuário não encontrado' })

  const valido = await bcrypt.compare(senha, users.senha)
  if (!valido) return res.status(401).json({ error: 'Senha inválida' })

  const token = jwt.sign({ id: users.id, email: users.email }, process.env.JWT_SECRET)
  res.json({ token, user: { id: users.id, nome: users.nome, email: users.email } })
})

// listar favoritos
app.get('/users/:id/favorites', auth, async (req, res) => {
  const { id } = req.params
  const { data, error } = await supabase
    .from('favorites')
    .select('*')
    .eq('user_id', id)

  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

// adicionar favorito
app.post('/users/:id/favorites', auth, async (req, res) => {
  const { id } = req.params
  const { musica_id } = req.body

  const { data, error } = await supabase
    .from('favorites')
    .insert([{ user_id: id, musica_id }])

  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

// remover favorito
app.delete('/users/:id/favorites/:musica_id', auth, async (req, res) => {
  const { id, musica_id } = req.params

  const { data, error } = await supabase
    .from('favorites')
    .delete()
    .eq('user_id', id)
    .eq('musica_id', musica_id)

  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

const PORT = process.env.PORT || 3000
app.listen(PORT, '0.0.0.0', () => console.log('Servidor rodando na porta', PORT))
