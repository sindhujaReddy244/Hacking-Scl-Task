require('dotenv').config()
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const {Client} = require('pg');
const jwt = require('jsonwebtoken');


// Creating an Express app.
const app = express();
app.use(cors())
app.use(bodyParser.json())


// Connection to the postgresql database.
const client = new Client({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database:process.env.DB_DATABASE,
    password:process.env.DB_PASSWORD,
    port:process.env.DB_PORT,

});

client.connect()
.then(() => {
    console.log('DB Connected')
})
.catch(err => {
    console.log('Error connecting to database', err)
})


const JWT_TOKEN = process.env.JWT_SECRET;
// Printing the JWT_SECRET 
//console.log('JWT_SECRET:', JWT_TOKEN);

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization');

  // Check if the token is missing
  if (!token) {
    return res.status(401).json({ message: 'Authentication token is missing' });
  }

  // Check if the token format is incorrect (missing "Bearer" prefix)
  if (!token.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Invalid token format' });
  }

  // Extract the token without the "Bearer" prefix
  const tokenWithoutBearer = token.slice(7);

  // Verify the token and check its expiration
  jwt.verify(tokenWithoutBearer, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ message: 'Token has expired' });
      } else {
        return res.status(403).json({ message: 'Invalid token' });
      }
    }

    // Token is valid, and you can access its payload in `decoded`
    req.user = decoded;
      next();
    });
  };


  //welcome
  app.get('/welcome', (req, res) => {
    res.send('welcome to node')
  })

  // Signup endpoint
app.post('/signup', async (req, res) => {
  console.log('Received signup request'); 
  try {
    const { username, password } = req.body;

    // Check if username or password is missing
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required' });
    }

    // Check if the username already exists in the database
    const userExists = await client.query('SELECT * FROM accounts WHERE username = $1', [username]);
    //console.log(username, password)

    if (userExists.rows.length > 0) {
      console.log('db password', userExists.password)
      return res.status(400).json({ message: 'Username already exists' });
    }

    // Hash and salt the password before storing it in the database
    const saltRounds = 10; // You can adjust this value for more or less security
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Store the username and hashed password in the database
    await client.query('INSERT INTO accounts (username, password) VALUES ($1, $2)', [username, hashedPassword]);
  
    res.status(201).json({ message: 'Registration successful' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Check if username or password is missing
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required' });
    }

    // Check if the username exists in the database
    const user = await client.query('SELECT * FROM accounts WHERE username = $1', [username]);
    

    if (user.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Compare the provided password with the hashed password in the database
    const passwordMatch = await bcrypt.compare(password, user.rows[0].password);
     
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Password Incorrect' });
    }

    // Generate a JWT token upon successful login
    const token = jwt.sign({ username: user.rows[0].username },  process.env.JWT_SECRET, {
      expiresIn: '11h', // Token expires in 11 hours
    });
    // console.log('jwt token', token);
    res.status(200).json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});




// Home page endpoint (requires authentication)
app.get('/home', authenticateToken, async (req, res) => {
    try {
      const { username } = req.user; // Extract the username from the authenticated user
      const { token } = req.headers; // Log the token to see its value
       console.log('Authenticated User:', username);
   // console.log('JWT Token:', JWT_TOKEN); 
  
      // Implement logic to fetch and paginate messages for the authenticated user
      const page = req.query.page || 1;
      const pageSize = 10; // Number of messages per page
      const startIndex = (page - 1) * pageSize;
      const endIndex = startIndex + pageSize;
  
      // Fetch messages for the user from the database 
      // const userMessages = await client.query('SELECT * FROM messages WHERE username = $1', [username]);
      const userMessages = await client.query('SELECT * FROM messages');

      if (!userMessages) {
        return res.status(404).json({ message: 'No messages found for this user' });
      }
      
      // Slice the messages based on the current page and page size
      const messagesForPage = userMessages.rows.slice(startIndex, endIndex);
  
      // Determine if there are more messages to load
      const hasMore = endIndex < userMessages.rows.length;
  
      res.json({ messages: messagesForPage, hasMore });
    } catch (error) {
      //console.error(error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
  
  

// Message submission endpoint (requires authentication)
app.post('/message', authenticateToken, async (req, res) => {
    try {
      const { content } = req.body;
  
      // Check if the message content is missing
      if (!content) {
        return res.status(400).json({ message: 'Message content is required' });
      }
  
      const username = req.user.username; // Extract the username from the authenticated user
  
      // Implement logic to save the message to the database
      await client.query('INSERT INTO messages (username, content, created_at) VALUES ($1, $2, NOW())', [username, content]);
  
      res.status(201).json({ message: 'Message submitted successfully' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
  

const PORT =  3002;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});