var mongoose = require('mongoose');

var TokenSchema = new nedb.Schema({
	
	//the actual token
	token : String,
	
	//timestamp
	date_created : {type: Date, default: Date.now}	
});

module.exports = mongoose.model('Token', TokenSchema);