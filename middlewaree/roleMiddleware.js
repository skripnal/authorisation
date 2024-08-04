const jwt = require('jsonwebtoken')
const { secret } = require('../config')
const Role = require('../models/Role')

module.exports = function (roles) {
    return function (req, res, next) {
        if (req.method === 'OPTIONS') {
            next()
        }

        try {
            const token = req.headers.authorization.split(' ')[1]
            if (!token) {
                return res.status(403).json('Користувач не авторизований!')
            }
            const { roles: userRoles } = jwt.verify(token, secret)
            let hasRole = false
            userRoles.forEach((role) => {
                if (roles.includes(role)) {
                    hasRole = true
                }
            })
            if (!hasRole) {
                return res.status(403).json('У вас немає доступу')
            }
            next()
        } catch (error) {
            console.log(error)
            return res.status(403).json('Користувач не авторизований!')
        }
    }
}
