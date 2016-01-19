var electron = require('electron'),
	Controller = electron.Controller;

var passport = require('passport'),
	User = require('../models/user');
	
var LoginController = new Controller()
