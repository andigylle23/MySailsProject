var mongoose = require('mongoose'),
	increment = require('mongoose-auto-increment'),
	bcrypt = require('bcrypt-nodejs'),
	jwt = require('jwt-simple'),
	secret = 'this-is-a-secret',
	SALT_WORK_FACTOR = 10;

//initialize moongoose connection
increment.initialize(mongoose.connection);

//require token
var Token = require('./token');

var UserSchema = new mongoose.Schema({
	
	//username
	username: {type: String, unique: true, required: true },
	
	//password
	password: {type: String, required: true},
	
	//email
	email : {type: String, unique: true, required: true}, 
	
	//access token
	token: Object,
	
	//timestamp
	date_create: {type: Date, default: Date.now}
},
{
	toObject: {virtuals: true},
	toJSON: {virtuals: true}
});

UserSchema.plugin(increment.plugin, 'User');

UserSchema.pre('save', function(next){
	var user = this;
	
	//break out if password wasnt change
	if(!user.isModified('password'))
		return next();
		
	bcrypt.genSalt(SALT_WORK_FACTOR, function(err, salt){
		if(err)
			return next(err);
		
		bcrypt.hash(user.password, salt, function(err, hash){
			if(err)
				return next(err);
			
			user.password = hash;
			next();
		});
	});
});

UserSchema.statics = {
	
	//create user
	createUser: function(data, callback){
		var User = mongoose.model ('User', UserSchema);
		
		var user = new User(data);
		
		//generate a hash
		user.status - require('crypto')
			.createHash('md5')
			.update(user.email + Math.random().toString())
			.digest('hex');
			
		user.save(function(err){
			return callback(err, user);
		});
	},
	
	//login user
	authenticate: function(username, password, callback){
		this.findOne({username: username}, function(err, user){
			
			//if error with mongo request
			if(err)
				return callback(err);
				
			//if no user found
			if(!user)
				return callback (null, false, {error: 'User does not exist.'});
			
			//password checking
			user.checkPassword(password, function(err, passwordCorrect){
				
				//error with mongo request
				if(err)
					return callback(err);
					
				//incorrect password
				if(!passwordCorrect)
					return callback(null, false, {error: "Password is incorrect"});
					
				return callback(null, user);
			});				
		});
	},
	
	//authenticate the token
	tokenthicate: function(token, callback){
		//if there no token
		if(!token)
			return callback	({error: 'You need a token'});
			
		this.findOne({'token.token': token}, function(err, user){
			
			//error with mongo request
			if(err)
				return callback(err);
			
			//token not found
			if(!user)
				return callback(null, false, {error: 'Token is invalid'});
			
			return callback(null, user);
		});
	},
	
	//create user token
	createUserToken: function(email, callback){
		
		var self = this;
		
		this.findOne({email: email}, function(err, user){
			
			//error with mongo request
			if(err)
				return callback(err);
			
			//no user found
			if(!user)
				return callback(null, false);
				
			var token = self.encode({email: email});
			
			user.token = new Token({token: token});
			user.save(function(err, user) {
				
				//erro with mongo request
				if(err)
					return callback(err);
					
				//return token
				callback(null, user.token);
			});
		});
	},
	
	//encode token
	encode: function(data){
		return jwt.encode(data, secret);
	},
	
	//decode token
	decode: function(data){
		return jwt.decode(data, secret);
	}
};

UserSchema.methods = {

	//password verification
	checkPassword: function (password, callback){
		
		bcrypt.compare(password, this.password, function(err, isMatch){
			
			if(err)
				return callback(err);
				
				callback(null, isMatch);
		});
	}	
};

module.exports = mongoose.model('User', UserSchema);