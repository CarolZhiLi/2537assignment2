require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');

const saltRounds = 12;
const expireTime = 1 * 60 * 60 * 1000;

const app = express();
const port = process.env.PORT || 3000;
const Joi = require("joi");

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

console.log(process.env.NODE_SESSION_SECRET);
require("./utils.js");
var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');

//Middleware to parse the body
app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore,
	saveUninitialized: false, 
	resave: true
}
));

//middleware
function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if(isValidSession(req)) {
        next();
    } else {
        res.redirect("/login");
    }   
}

function isAdmin(req) {
    if(req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req,res,next) {
    if(!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized"});
        return;
    } else {
        next();
    }
}


app.get('/',(req,res) => {
    res.render("index");
});

app.get('/signup/', (req,res) => {
    res.render("signup");
});

app.post('/signupSubmit', async(req,res) => {
    const {username, email, password} = req.body;
    //console.log(username);
    //console.log(email);
    //console.log(password);
    let errors = [];
    if (!username) errors.push('Username');
    if (!email) errors.push('Email');
    if (!password) errors.push('Password');

    if (errors.length > 0) {
        res.render("signupSubmit", {errors:errors});
    } else {
    
        const schema = Joi.object(
            {
                username: Joi.string().alphanum().max(20).required(),
                email: Joi.string().required(),
                password: Joi.string().min(8).required()
            });
        const validationResult = schema.validate({username, email, password});
        if (validationResult.error != null) {
            console.log(validationResult.error);
            res.redirect("/signup");
            return;
        }
        var hashedPassword = await bcrypt.hash(password, saltRounds);
        
        await userCollection.insertOne({username: username, email: email, password: hashedPassword});
        console.log("Added user");
        req.session.authenticated = true;
        req.session.username = username;
        req.session.cookie.maxAge = expireTime;
        res.redirect("/members");
    }
});

app.get('/login/', (req,res) => {
    res.render("login");
});

app.post('/loginSubmit', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

    //console.log(email);
    //console.log(password);
	const schema = Joi.object(
		{
            email: Joi.string().required(),
			password: Joi.string().min(8).required()
		});
	const validationResult = schema.validate({email, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
       res.render("loginSubmit");
	   return;
	}
    
	const result = await userCollection.find({email: email}).project({username: 1, email: 1, password: 1, user_type: 1, _id: 1}).toArray();   
	//console.log(result);
    //console.log(result[0].username);

	if (result.length != 1) {
		console.log("user not found");
		res.render("loginSubmit");
	    return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
        req.session.username = result[0].username;
        req.session.user_type = result[0].user_type;
		req.session.cookie.maxAge = expireTime;
        
		res.redirect("/members");
		return;
	}
	else {
		console.log("incorrect password");
		res.render("loginSubmit");
	    return;
	}
});


app.get('/members', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect("/");
        return;
    }
    const name = req.session.username;
    //console.log(name);
    res.render("members", {name: name});
});



app.get('/logout', (req,res) => {
    req.session.destroy();
    res.redirect("/");
});

app.get('/admin', sessionValidation, adminAuthorization, async(req,res) => {
    const result = await userCollection.find().project({username:1, user_type: 1, _id:1}).toArray();
    //console.log(result);
    res.render("admin", {user:result});
});

app.post('/changeType', async(req, res) => {
    const {targetType} = req.body;
    const username = req.query.username;
    //console.log(username, targetType);
    const user = await userCollection.find({username: username}).project({username:1, user_type: 1, _id:1});
    if (user) {
        await userCollection.updateOne({username: username}, {$set: {user_type: targetType}});
    }
    res.redirect('/admin');
})

app.use(express.static(__dirname + "/public"));


app.get("*", (req,res) => {
	res.render("404");
});

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 