// https://github.com/mikelopster/auth-express-example/blob/main/index.js
const express = require('express')
const mysql = require('mysql2/promise')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const cors = require('cors')
require('dotenv').config()
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const app = express()
const port = process.env.PORT || 3000
const secret = ''

const initMySQL = async () => {
    conn = await mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: '123456',
        database: 'ecom'
    })
}

app.use(express.json())
app.use(cors({
    credentials: true,
    origin: [`http://localhost:${port}`]
}))

app.listen(port, async () => {
    await initMySQL();
    console.log(`Server started at port ${port}`)
})

app.post('/auth/jwt/login', async (req, res) => {
    try {
        const { username, password } = req.body

        const [users] = await conn.query('SELECT * from user WHERE username = ?', username)
        const user = users[0]

        const match = await bcrypt.compare(password, user.password)

        const [roles] = await conn.query('SELECT * from role WHERE id = ?', user.role_id)
        const role = roles.map(x => x.title)


        if (!match) {
            return res.status(400).send({ message: 'Invalid email or password' })
        }

        const token = generateToken(user, role)
        const refreshToken = generateRefreshToken(user)

        // res.cookie('token', token, {
        //     maxAge: 300000,
        //     secure: true,
        //     httpOnly: true,
        //     sameSite: "none",
        // })

        // req.session.userId = user.id
        // console.log('save session', req.session.userId)

        res.send({
            token,
            refreshToken
        })
    } catch (error) {
        return res.status(401).json({
            message: error.message
        })
    }
})

// app.post("/auth/refresh", jwtRefreshTokenValidate, (req, res) => {
//     const user = users.find(
//         (e) => e.id === req.user.id && e.name === req.user.name
//     )

//     const userIndex = users.findIndex((e) => e.refresh === req.user.token)

//     if (!user || userIndex < 0) return res.sendStatus(401)

//     const access_token = jwtGenerate(user)
//     const refresh_token = jwtRefreshTokenGenerate(user)
//     users[userIndex].refresh = refresh_token

//     return res.json({
//         access_token,
//         refresh_token,
//     })
// })

// ==== middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    // const token = req.cookies.token
    // console.log('session', req.session.userId)

    if (token == null) return res.sendStatus(401)

    try {
        const user = jwt.verify(token, secret)
        req.user = user
        console.log('user', user)
        next()
    } catch (error) {
        return res.sendStatus(403)
    }
}

const jwtRefreshTokenValidate = (req, res, next) => {
    try {
        if (!req.headers["authorization"]) return res.sendStatus(401)
        const token = req.headers["authorization"].replace("Bearer ", "")

        jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, decoded) => {
            if (err) throw new Error(error)

            req.user = decoded
            req.user.token = token
            delete req.user.exp
            delete req.user.iat
        })
        next()
    } catch (error) {
        return res.sendStatus(403)
    }
}

// const generateToken = (userDetails) => {
//     Claims claims = Jwts.claims().subject(userDetails.getId()).add(CLAIM_KEY_ROLE, userDetails.getAuthorities().stream().map(s -> s.getAuthority()).collect(Collectors.toList())).build();

//     return doGenerateToken(claims, generateAudience());
// }

// const createSignature =(jwtB64Header,jwtB64Payload,secret)=>{
// // create a HMAC(hash based message authentication code) using sha256 hashing alg
//     let signature = crypto.createHmac ('sha256', secret);

// // use the update method to hash a string formed from our jwtB64Header a period and 
// //jwtB64Payload 
//     signature.update (jwtB64Header + '.' + jwtB64Payload);

// //signature needs to be converted to base64 to make it usable
//     signature = signature.digest ('base64');

// //of course we need to clean the base64 string of URL special characters
//     signature = replaceSpecialChars (signature);
//     return signature
// }

// function generateSignature (str, secret) {
//     return crypto
//         .createHmac('sha256', secret)
//         .update(str)
//         .digest('base64')
//         .replace(/\+/g, '-')
//         .replace(/\//g, '_')
//   }
// https://www.borntodev.com/2023/11/01/การใช้งาน-jwt-json-web-tokens-ในการ-authentication/
// https://medium.com/@guseynism/simple-jwt-implementation-in-node-js-symmetric-variation-284a02b0bec9
const generateToken = (user, roles) => {
    // create your secret to sign the token
    // const secret = 'super_secret_society';
    // const signature = createSignature(jwtB64Header,jwtB64Payload,secret);
    // var base64decode = atob(process.env.ACCESS_TOKEN_SECRET);
    // Decode the Base64 encoded key
    // const keyBytes = Buffer.from(base64decode, 'base64');
    // const keyBytes = Buffer.from(process.env.ACCESS_TOKEN_SECRET);
    // Specify the algorithm
    // const algorithm = 'sha512';
    // Create the HMAC key using the decoded bytes and the algorithm
    // const secretKey = crypto.createHmac(algorithm, keyBytes);


    const iss = process.env.JWT_ISSUER
    const aud = ["unknown"]
    const accessToken = jwt.sign(
        { sub: user.username, roles, iss, aud },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "15m" }
    )

    return accessToken
}

const generateRefreshToken = (user) => {
    const iss = process.env.JWT_ISSUER
    const aud = ["unknown"]
    const scopes = ["refresh_token"]
    const jti = uuidv4()
    const refreshToken = jwt.sign(
        { sub: user.username, iss, aud, scopes, jti },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: "1d", algorithm: "HS256" }
    )

    return refreshToken
}