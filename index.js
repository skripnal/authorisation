const express = require('express')
const cors = require('cors')
const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')
const bodyParser = require('body-parser')
const { check, validationResult } = require('express-validator')
const jwt = require('jsonwebtoken')

const User = require('./models/User')
const Role = require('./models/Role')
const { secret } = require('./config')
const authMiddleware = require('./middlewaree/authMiddleware')
const roleMiddleware = require('./middlewaree/roleMiddleware')

const app = express()

app.use(cors())
app.use(bodyParser.json())

const generateAccesToken = (id, roles) => {
    const payload = {
        id,
        roles,
    }
    return jwt.sign(payload, secret, { expiresIn: '24h' })
}

app.post(
    '/auth/registration',
    [
        check('username', 'Імʼя користувача не може бути порожнім').notEmpty(),
        check(
            'password',
            'Пароль повинен мати не менше 4 символів і не більше 10'
        ).isLength({ min: 4, max: 10 }),
        check('password', 'Пароль не повинен бути порожнім').notEmpty(),
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req)
            if (!errors.isEmpty()) {
                return res
                    .status(400)
                    .json({ message: 'Помилка при валідації', errors })
            }
            const { username, password } = req.body
            const candidate = await User.findOne({ username })
            if (candidate) {
                return res
                    .status(400)
                    .json({ message: 'Користувач з таки імʼям вже існує!' })
            }
            const hashPassword = bcrypt.hashSync(password, 7)
            const userRole = await Role.findOne({ value: 'USER' })
            const user = new User({
                username,
                password: hashPassword,
                roles: [userRole.value],
            })
            await user.save()
            return res.json({
                message: 'Користувач був успішно зареєстований!',
            })
        } catch (error) {
            console.log(error)
            res.status(400).json({ message: 'Registration error' })
        }
    }
)

app.post('/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body
        const user = await User.findOne({ username })
        if (!user) {
            return res
                .status(400)
                .json({ message: `Користувач ${username} не знайдений` })
        }
        const validPassword = bcrypt.compareSync(password, user.password)
        if (!validPassword) {
            return res
                .status(400)
                .json({ message: `Введено неправильний пароль` })
        }
        const token = generateAccesToken(user._id, user.roles)
        return res.json({ token })
    } catch (error) {
        console.log(error)
        res.status(400).json({ message: 'Login error' })
    }
})

app.get('/auth/users', roleMiddleware(['USER', 'ADMIN']), async (req, res) => {
    try {
        const users = await User.find()
        res.json(users)
    } catch (error) {
        console.log(error)
    }
})

const port = process.env.PORT || 4000

const start = async () => {
    try {
        await mongoose.connect(
            `mongodb+srv://skripnal:jyCTAQWILmDMtPdF@cluster0.1udkz6c.mongodb.net/auth_roles?retryWrites=true&w=majority&appName=Cluster0`
        )

        app.listen(port, () => {
            console.log(`Server is running on port ${port}`)
        })
    } catch (error) {
        console.log(error)
    }
}

start()
