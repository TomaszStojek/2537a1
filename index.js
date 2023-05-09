
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
const { error } = require("selenium-webdriver");


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

app.set('view engine', 'ejs');

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

function getRandNum1to3() {
    return Math.floor(Math.random() * 3) + 1;
  }

  function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}


app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
    const result = await userCollection.find().project({username: 1,user_type: 1, _id: 1}).toArray();
 
    res.render("admin", {users: result});
});

app.get('/', (req, res) => {
    if (!req.session.authenticated) {
        res.render('index', { authenticated: false });
    } else {
        var name = req.session.name;
        res.render('index', { authenticated: true, name: name });
    }
});

app.get('/createUser', (req,res) => {
   res.render("createUser");
});

app.get('/login', (req,res) => {
    var wrongPasswordorUsername = req.query.wrong;
    res.render("login", {wrongPasswordorUsername: wrongPasswordorUsername});
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
       let error = validationResult.error;
         res.render('tryAgain', {error: error}
       
	   );
	   return;
   }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
    await userCollection.insertOne({username: username, password: hashedPassword, user_type: "user"});
	console.log("Inserted user");
    
    req.session.name = name;
    req.session.authenticated = true;
    res.render('members', { type: getRandNum1to3() });
});

app.post('/loggingin', async (req, res) => {
    var username = req.body.username;
    var password = req.body.password;

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.render('login', { wrongPasswordorUsername: true });
        return;
    }

    const result = await userCollection.find({username: username}).project({username: 1, password: 1, user_type: 1, _id: 1}).toArray();

    console.log(result);
    if (result.length != 1) {
        console.log("user not found");
        res.render('login', { wrongPasswordorUsername: true});
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.username = username;
        req.session.user_type = result[0].user_type;
        req.session.name = result[0].name;
        req.session.cookie.maxAge = expireTime;

        res.render('members', { type: getRandNum1to3() });
        return;
    } else {
        console.log("incorrect password");
        res.render('login', { wrongPasswordorUsername: true });
        return;
    }
});


app.get('/logout', (req,res) => {
	req.session.destroy();
    res.render("index" , {authenticated: false});
});

app.get('/members', (req,res) => {
    if (!req.session.authenticated) {
        res.render('index', { authenticated: false });
    }
else {
res.render("members", {type: getRandNum1to3()});
}
});

app.post('/updateUser', async (req, res) => {
  const username = req.body.username;
  const userType = req.body.userType;
  const action = req.body.action;

  try {
    const user = await userCollection.findOne({ username });

    if (!user) {
      // User not found
      res.status(404);
      res.render('errorMessage', { error: 'User not found' });
      return;
    }

    if (action === 'promote') {
      // Promote the user to admin
      await userCollection.updateOne(
        { username },
        { $set: { user_type: 'admin' } }
      );
    } else if (action === 'demote') {
      // Demote the user to a regular user
      await userCollection.updateOne(
        { username },
        { $set: { user_type: 'user' } }
      );
    }

    res.redirect('/admin');
  } catch (error) {
    console.error(error);
    res.status(500).render('errorMessage', { error: 'Internal Server Error' });
  }
});

  
  
  
  


//test
app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.render("404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 
