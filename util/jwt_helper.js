const jwt = require("jsonwebtoken");
require('dotenv').config()

exports.generateAccessToken = async (userId) => {
    return new Promise((resolve, reject) => {
        try {
            const token = jwt.sign(
                { userId: userId },
                process.env.TOKEN_KEY,
                { expiresIn: "30s" }
            );
            resolve(token)
        } catch (err) {
            reject(err)
        }
    });
}

exports.generateRefreshToken = async (userId) => {
    return new Promise((resolve, reject) => {
        try {
            const refToken = jwt.sign(
                { userId: userId },
                process.env.REFRESH_TOKEN_KEY,
                { expiresIn: "30d" }
            );
            resolve(refToken)
        } catch (err) {
            reject(err)
        }
    });
}

exports.verifyRefreshToken = async (refreshToken) => {
    return new Promise(async (resolve, reject) => {
        try {
            const refToken = await jwt.verify(refreshToken, process.env.REFRESH_TOKEN_KEY);
            console.log(refToken)
            resolve(refToken)
        } catch (err) {
            reject(err)
        }
    });
}

