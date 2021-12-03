const express = require('express');
const app = express();
require('dotenv').config()

app.use(express.json());

const db = require('./db/db');

const userRoutes = require('./routes/user_route');
app.use('/user', userRoutes);

const PORT = 3000;


app.listen(PORT, () => {
    console.log(`Listening on port ${PORT}`)
});

//