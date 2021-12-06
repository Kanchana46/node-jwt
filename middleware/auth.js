const jwt = require("jsonwebtoken");
require('dotenv').config()

module.exports = (req, res, next) => {
    const token = req.headers["authorization"];
    if (!token) {
        return res.status(403).send("Unauthorized");
    }
    try {
        const decoded = jwt.verify(token, process.env.TOKEN_KEY);
        req.user = decoded
        //console.log(req.user)
    } catch (err) {
        //console.log(err)
        return res.status(401).send(err.message);
    }
    return next()
}
