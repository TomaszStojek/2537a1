
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");


const expireTime = 1 * 60 * 60 * 1000; //expires after one hour

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

app.get('/', (req,res) => {
    if (!req.session.authenticated) {
       
    res.send(`
        <h1>Welcome!</h1>
        <ul>
            <li><a href="/createUser">Create User</a></li>
            <li><a href="/login">Login</a></li>
        </ul>
    `);
    } 
    
    else {
        var name = req.session.name;
        var string = '<h1>Hello, ' + name  + '!</h1>';
        res.send(string + `
    
    <ul>
        <li><a href="/logout">Log out</a></li>
        <li><a href="/members">members area</a></li>
    </ul>
`);
    }
});



app.get('/createUser', (req,res) => {
    var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='email'>
    <input name='name' type='text' placeholder='name'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});


app.get('/login', (req,res) => {
    var wrongPasswordorUsername = req.query.wrong;
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='username' type='text' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    if (wrongPasswordorUsername) {
        html += "<br> wrong password or username";
    }
    res.send(html);
    res.send(html);
});

app.post('/submitUser', async (req,res) => {
    var username = req.body.username;
    var password = req.body.password;
    var name = req.body.name;

	const schema = Joi.object(
		{
            username: Joi.string().email().required(),
			name: Joi.string().alphanum().max(20).required(),
			password: Joi.string().max(20).required()
		});
	
	const validationResult = schema.validate({username, name, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
       
	   res.send('<h1>' + validationResult.error + '</h1>' + '<br><a href="/createUser">try again</a>');
	   return;
   }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({username: username, password: hashedPassword, name: name});
	console.log("Inserted user");
    
    req.session.name = name;
    req.session.authenticated = true;
    res.redirect('/members');
});

app.post('/loggingin', async (req,res) => {
    var username = req.body.username;
    var password = req.body.password;

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({username: username}).project({name: 1, username: 1, password: 1, _id: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
		console.log("user not found");
		res.redirect("/login");
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.username = username;
        req.session.name = result[0].name;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/members');
		return;
	}
	else {

		console.log("incorrect password");
		res.redirect("/login?wrong=1");
		return;
	}
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/');
});

app.get('/members', (req,res) => {
    let type = Math.floor(Math.random() * 3) + 1;
    let logout = '<a href="/logout">Log Out</a>';
    if (!req.session.authenticated) {
        res.redirect('/');
        

    } else if (type == 1) {
        let name = req.session.name;
        let string = '<h1>Hello, ' + name  + '!</h1>';
        
        res.send(string + "Beach: <img src='/beach.gif' style='width:250px;'>" + logout);
    }
    else if (type == 2) {
        let name = req.session.name;
        let string = '<h1>Hello, ' + name  + '!</h1>';
        res.send(string + "Indoor: <img src='/indoor.gif' style='width:250px;'>" + logout);
    }
    else if (type == 3) {
        let name = req.session.name;
        let string = '<h1>Hello, ' + name  + '!</h1>';
        res.send(string + "Grass: <img src='/grass.jpg' style='width:250px;'>" + logout);
    }
    else {
        res.send("Invalid type id: "+type);
    }
});


//test
app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 
