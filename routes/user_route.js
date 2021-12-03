const express = require('express');
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const auth = require("../middleware/auth");
const { v4: uuidv4 } = require('uuid');

const User = require("../model/user_model");
const UserToken = require("../model/userToken_model");

router.post('/register', async (req, res) => {
    try {
        const { first_name, last_name, email, password } = req.body;
        console.log(req.body)
        const isUserExists = await User.findOne({ email })

        if (isUserExists) {
            res.send("User already exists.")
        }
        const salt = await bcrypt.genSaltSync(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const user = await User.create({
            first_name,
            last_name,
            email,
            password: hashedPassword
        })

        res.status(200).json(user);

    } catch (err) {
        console.log(err);
    }
});


router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        const isPasswordMatched = await bcrypt.compare(password, user.password);
        if (user) {
            if (isPasswordMatched) {
                const token = jwt.sign(
                    { userId: user._id },
                    process.env.TOKEN_KEY,
                    { expiresIn: "30s" }
                );

                user.token = token;
                const refToken = uuidv4()
                await UserToken.create({
                    userId: user._id,
                    refreshToken: refToken,
                    createdAt: new Date()
                })

                res.status(200).json({
                    userId: user._id,
                    token: token,
                    refreshToken: refToken
                });
            }
        } else {
            res.status(400).json('Invalid credentials');
        }
    } catch (err) {
        console.log(err);
    }
});


router.get('/doSomeWork', auth, (req, res) => {
    res.status(200).send("You are authenticated");
});


router.post('/refreshToken', async (req, res) => {
    const token_object = await UserToken.find({ userId: req.body.userId }).sort({ createdAt: -1 }).limit(1);
    console.log(token_object)
    if (token_object.length == 0) {
        res.send("Refresh token does not exist")
    } else {
        const refreshToken = token_object[0].refreshToken;
        if (refreshToken == req.body.refreshToken) {
            const token = jwt.sign(
                { userId: req.body.userId },
                process.env.TOKEN_KEY,
                { expiresIn: "30s" }
            );
            res.json({ token: token })
        }
    }
});


module.exports = router;