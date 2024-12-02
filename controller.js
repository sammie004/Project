const mysql = require("mysql")
const express = require("express")
const app = express()
const bcrypt = require("bcrypt")
const bodyParser = require("body-parser")
const jwt = require('jsonwebtoken')
const dotenv = require("dotenv")
dotenv.config()
app.use(express.json())
app.use(bodyParser.urlencoded({extended:true}))
// database connection
const newConn = mysql.createConnection({
    host : process.env.DB_HOST,
    user : process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database : process.env.DB_DATABASE
})
// token authentication middleware
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    console.log("Token from Authorization header:", token);
    if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
}
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token.' });
        req.user = user;
        next();
    });
};
// connection testing
newConn.connect((error)=>{
    if(error){
        console.log(`there was an error connecting to the database`)
    }else{
        console.log(`a connection to the database was successfully established`)
    }
})
// user authentication
app.post('/sign-up', (req, res) => {
    const { username, password } = req.body;
    console.log('Sign-Up Request Body:', req.body);

    const exists = 'select * from centraladmin where username = ?';
    newConn.query(exists, [username], async (err, results) => {
        if (err) {
            console.error('Database Error:', err.message);
            return res.status(500).json({ message: 'Internal server error' });
        }
        console.log('User Exists Check:', results);

        if (results.length > 0) {
            return res.status(400).json({ message: 'User already exists' });
        } else {
            const saltRounds = 10;
            const hashed_password = await bcrypt.hash(password, saltRounds);
            console.log('Hashed Password:', hashed_password);
            const create_new_user = 'insert into central_admin (username, password) values (?, ?)';
            newConn.query(create_new_user, [username, hashed_password], (err, results) => {
                if (err) {
                    console.error('Error Inserting User:', err.message);
                    return res.status(500).json({ message: 'Error creating user' });
                }
                return res.status(201).json({ message: `Welcome ${username}` });
            });
        }
    });
});

app.post('/sign-in', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        console.log('Username or password not provided');
        return res.status(400).json({ message: 'Please provide both username and password' });
    }

    const search = 'SELECT * FROM central_admin WHERE username = ?';
    
    newConn.query(search, [username], async (err, results) => {
        if (err) {
            console.error('Database error occurred:', err.message);
            return res.status(500).json({ message: 'Internal server error' });
        }

        if (results.length === 0) {
            console.log(`User not found for username: ${username}`);
            return res.status(404).json({ message: 'User not found' });
        }

        const user = results[0];

        try {
            console.log('Plain Password (Sign-In):', password);
            console.log('Hashed Password (From DB):', user.password);

            const isPasswordMatch = await bcrypt.compare(password, user.password);

            if (isPasswordMatch) {
                console.log(`Successful login attempt for username: ${username}`);
                const token = jwt.sign(
                    { userId: user.id, username: user.username },
                    process.env.JWT_SECRET,
                    { expiresIn: '1h' }
                );

                console.log(`Generated token for user: ${username}`);
                return res.status(200).json({
                    message: `Welcome ${username}`,
                    token
                });
            } else {
                console.log(`Password mismatch for username: ${username}`);
                return res.status(400).json({ message: 'Invalid username or password' });
            }
        } catch (error) {
            console.error('Error comparing passwords:', error.message);
            return res.status(500).json({ message: 'Error processing your request' });
        }
    });
});

// logout
app.post('/logout', authenticateToken, (req, res) => {
    res.status(200).json({ message: "Logout successful. Please remove the token on the client side." });
});
// app.post('logout',(req,res)=>{})
app.listen(process.env.PORT,()=>{
    console.log(`the server is running on port ${process.env.PORT}`)
})