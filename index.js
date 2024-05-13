const dotenv = require('dotenv')
const express = require('express')
const cookieparser = require('cookie-parser')
const jwt = require('jsonwebtoken')
const bodyParser = require('body-parser')
const activateEmailTemplate = require('./template/activateEmailTemplate')
const resetEmailTemplate = require('./template/resetEmailTemplate')
const nodemailer = require('nodemailer')
const { google } = require('googleapis')
const { OAuth2 } = google.auth
const OAUTH_PLAYGROUND = 'https://developers.google.com/oauthplayground'
const validateEmail = require('./util/validateEmail')

// Configuring dotenv
dotenv.config()
const app = express()

// Setting up middlewares to parse request body and cookies
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieparser())

const userCredentials = {
  username: 'admin',
  password: 'admin123',
  email: 'admin@gmail.com',
}

app.post('/login', (req, res) => {
  // Destructuring username & password from body
  const { username, password, token } = req.body

  const decodedToken = jwt.verify(
    token,
    process.env.REFRESH_TOKEN_SECRET,
    (err, decoded) => {
      return err
    }
  )

  function formatJWTExp(exp) {
    const expDate = new Date(exp * 1000) // 將秒數轉為毫秒
    const year = expDate.getFullYear()
    const month = String(expDate.getMonth() + 1).padStart(2, '0') // 月份從0開始，需要加1，補0
    const day = String(expDate.getDate()).padStart(2, '0')
    const hour = String(expDate.getHours()).padStart(2, '0')
    const minute = String(expDate.getMinutes()).padStart(2, '0')
    const formattedExp = `${year}-${month}-${day}T${hour}:${minute}+02:00` // 假設時區為+02:00
    return formattedExp
  }
  const formatJWT = formatJWTExp(decodedToken)

  const currentTime = Math.floor(Date.now() / 1000)
  const state = false

  if (formatJWT - currentTime < 3600) {
    // 假設設置為1小時
    state = true
  }

  if (!decodedToken) {
    // Refresh Token 已經過期或解析失敗
    return false
  }

  // Checking if credentials match
  if (
    username === userCredentials.username &&
    password === userCredentials.password
  ) {
    //creating a access token
    const accessToken = jwt.sign(
      {
        username: userCredentials.username,
        email: userCredentials.email,
      },
      process.env.ACCESS_TOKEN_SECRET,
      {
        expiresIn: '10s',
      }
    )
    // Creating refresh token not that expiry of refresh
    //token is greater than the access token

    const refreshToken = jwt.sign(
      {
        username: userCredentials.username,
      },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: '60s' }
    )

    // Assigning refresh token in http-only cookie
    res.cookie('jwt', refreshToken, {
      httpOnly: true,
      sameSite: 'None',
      secure: true,
      maxAge: 24 * 60 * 60 * 1000,
    })
    return res.json({
      accessToken,
      refreshToken,
      decodedToken,
      currentTime,
      state,
    })
  } else {
    // Return unauthorized error if credentials don't match
    return res.status(406).json({
      message: 'Invalid credentials',
    })
  }
})

app.post('/refresh', (req, res) => {
  if (req.cookies?.jwt) {
    console.log(req.cookies.jwt)
    // Destructuring refreshToken from cookie
    const refreshToken = req.cookies.jwt

    // Verifying refresh token
    jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET,
      (err, decoded) => {
        if (err) {
          // Wrong Refesh Token
          return res.status(406).json({ message: 'Unauthorized' })
        } else {
          // Correct token we send a new access token
          const accessToken = jwt.sign(
            {
              username: userCredentials.username,
              email: userCredentials.email,
            },
            process.env.ACCESS_TOKEN_SECRET,
            {
              expiresIn: '1m',
            }
          )
          return res.json({ accessToken })
        }
      }
    )
  } else {
    return res.status(406).json({ message: 'Unauthorized' })
  }
})

// send email
app.post('/sendEmail', (req, res) => {
  if (!req.body.email || !req.body.subject)
    return res.status(400).json({ message: '請填寫 Email 或 信件主旨 subject' })

  if (!validateEmail(req.body.email))
    return res.status(400).json({ message: '請填寫正確 Email 格式' })

  const SENDER_EMAIL_TO = req.body.email
  const SENDER_EMAIL_SUBJECT = req.body.subject

  const {
    MAILING_SERVER_CLIENT_ID,
    MAILING_SERVER_CLIENT_SECRET,
    MAILING_SERVER_REFRESH_TOKEN,
    SENDER_EMAIL_ADDRESS,
  } = process.env

  const oauth2Client = new OAuth2(
    MAILING_SERVER_CLIENT_ID,
    MAILING_SERVER_CLIENT_SECRET,
    MAILING_SERVER_REFRESH_TOKEN,
    OAUTH_PLAYGROUND
  )

  oauth2Client.setCredentials({
    refresh_token: MAILING_SERVER_REFRESH_TOKEN,
  })
  const accessToken = oauth2Client.getAccessToken()
  const smtpTransport = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      type: 'OAuth2',
      user: SENDER_EMAIL_ADDRESS,
      clientId: MAILING_SERVER_CLIENT_ID,
      clientSecret: MAILING_SERVER_CLIENT_SECRET,
      refreshToken: MAILING_SERVER_REFRESH_TOKEN,
      accessToken,
    },
  })
  // 信件模板可以自由替換主題，自行設計參數代入
  const mailOptions = {
    from: SENDER_EMAIL_ADDRESS,
    to: SENDER_EMAIL_TO,
    subject: SENDER_EMAIL_SUBJECT,
    html: resetEmailTemplate(
      'https://github.com/Journey-bites',
      'https://github.com/Journey-bites'
    ),
  }

  smtpTransport.sendMail(mailOptions, (err, infos) => {
    if (err) return res.status(200).json({ err })
    return res.status(200).json({ message: infos })
  })
})

process.on('uncaughtException', (err) => {
  console.log(err)
  process.exit(1)
})

process.on('unhandledRejection', (reason, promise) => {
  console.log('未捕捉錯誤', promise, '原因', reason)
})

app.get('/', (req, res) => {
  res.send('Server')
  console.log('server running')
})

app.listen(8000, () => {
  console.log(`Server active on http://localhost:${8000}!`)
})
