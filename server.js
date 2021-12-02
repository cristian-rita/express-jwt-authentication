const express = require('express')
const jwtDecode = require('jwt-decode')
const jsonwebtoken = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const randToken = require('rand-token'); 
const cors = require('cors')
const mongoose = require('mongoose')
const jwt = require('express-jwt');
const axios = require('axios');

const app = express()
const port = 3000

const SECRET = 'changeme';

const User = require('./model/User');
const Token = require('./model/Token');

app.use(cors())
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

const generateToken = user => {
 
    const token = jsonwebtoken.sign({
    sub: user._id,
    email: user.email,
    aud: 'api.example.com',
    iss: 'api.example.com',
  }, SECRET, {
    expiresIn: '1h',
    algorithm: 'HS256'
  })
 
 
  return token
}

const hashPassword = password => {
  return new Promise((resolve, reject) => {
    bcrypt.genSalt(10, (err, salt) => {
      if(err) reject(err)
      bcrypt.hash(password, salt, (err, hash) => {
        if(err) reject(err)
        resolve(hash)
      })
    })
  })
}

const checkPassword = (password, hash) => bcrypt.compare(password, hash)

const getRefreshToken = () => randToken.uid(256)

// API ENDPOINTS 

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body
    const user = await User.findOne({ email })
    if (!user) { 
        return res.status(401).json({
            message: 'User not found!'
        })
      }
    const isPasswordValid = await checkPassword(password, user.password)
  
    if(!isPasswordValid) {
        return res.status(401).json({
            message: 'Invalid password!'
    })}
    const accessToken = generateToken(user)
    const decodedAccessToken = jwtDecode(accessToken)
    const accessTokenExpiresAt = decodedAccessToken.exp
    const refreshToken = getRefreshToken(user)

    const storedRefreshToken = new Token({ refreshToken, user: user._id })
    await storedRefreshToken.save()

    res.json({
        accessToken,
        expiresAt: accessTokenExpiresAt,
        refreshToken
    })
})

app.post('/api/register', async (req, res) => {

  const { email, password, firstName, lastName } = req.body

  const hashedPassword = await hashPassword(password)
  const userData = {
    email: email,
    firstName: firstName,
    lastName: lastName,
    password: hashedPassword,
  }

  const existingUser = await User.findOne({ email: email }).lean()

  if(existingUser) {
    return res.status(400).json({
      message: 'Email already exists'
    })
  }

  const user = new User(userData)
  const savedUser = await user.save()

  if(savedUser) {
    const accessToken = generateToken(savedUser);
    const decodedToken = jwtDecode(accessToken);
    const expiresAt = decodedToken.exp;

    return res.status(200).json({
      message: 'User created successfully',
      accessToken,
      expiresAt,
      refreshToken: createRefreshToken(savedUser),
    })
  }
})


app.post('/api/refreshToken', async (req, res) => {
  const {refreshToken } = req.body
  try {
    const user = await Token.findOne({refreshToken}).select('user')

    if(!user) {
      return res.status(401).json({
        message: 'Invalid token'
      })
    }

    const existingUser = await User.findOne({_id: user.user})

    if(!existingUser) {
      return res.status(401).json({
        message: 'Invalid token'
      })
    }

    const token = generateToken(existingUser)
    return res.json({accessToken: token})
  } catch (err) {
    return res.status(500).json({message: 'Could not refresh token'})
  }
})

const attachUser = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    return res
      .status(401)
      .json({ message: 'Authentication invalid' });
  }
  const decodedToken = jwtDecode(token.slice(7));

  if (!decodedToken) {
    return res.status(401).json({
      message: 'There was a problem authorizing the request'
    });
  } else {
    req.user = decodedToken;
    next();
  }
};

app.use(attachUser);

const requireAuth = jwt({
  secret: SECRET,
  audience: 'api.example.com',
  issuer: 'api.example.com',
  algorithms: ['HS256']
});


app.get('/api/cat',requireAuth, async (req, res) => {
   const response = await axios.get('https://cataas.com/cat', { responseType:"arraybuffer" })
   let raw = Buffer.from(response.data).toString('base64');
   res.send("data:" + response.headers["content-type"] + ";base64,"+raw);

})

async function connect() {
  try {    
    mongoose.Promise = global.Promise;
    await mongoose.connect("mongodb://localhost:27017", {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
  } catch (err) {
    console.log('Mongoose error', err);
  }
  app.listen(port);
  console.log(`Server listening on port ${port}`);
}


connect();
