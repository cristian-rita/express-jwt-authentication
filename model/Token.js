
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const tokenModel = new Schema({
    refreshToken: {type: String, required: true},
    user: { type: Schema.Types.ObjectId, required: true, ref: 'User' }
})

module.exports = mongoose.model('Token', tokenModel);