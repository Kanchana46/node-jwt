const mongoose = require("mongoose");

const userTokenSchema = new mongoose.Schema({
    userId: { type: String, default: null },
    refreshToken: { type: String, default: null },
    createdAt: {
        type: Date,
        default: null,
    }
})

module.exports = mongoose.model("userToken", userTokenSchema);