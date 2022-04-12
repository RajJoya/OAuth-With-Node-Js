//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const findOrCreate = require("mongoose-findorcreate");

const app = express();
const mongoose = require("mongoose");

const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");


const GoogleStrategy = require('passport-google-oauth20').Strategy;
var MicrosoftStrategy = require('passport-microsoft').Strategy;
const GitHubStrategy = require('passport-github').Strategy;
const LinkedInStrategy = require('passport-linkedin').Strategy;

const encrypt = require("mongoose-encryption");
const md5 = require("md5")
const bcrypt = require("bcrypt");
const saltRounds = 10;


app.set("view engine","ejs");
app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));


app.use(session({
	secret: "Our little secret.",
  	resave: false,
  	saveUninitialized: false
	// cookie:{secure:true}
}));




app.use(passport.initialize());
app.use(passport.session());




mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
	email:String,
	password:String,
	googleId: String,
	// provider:String
	MS_Id:String,
	githubId:String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


// var LINKEDIN_API_KEY = "--insert-linkedin-api-key-here--";
// var LINKEDIN_SECRET_KEY = "--insert-linkedin-secret-key-here--";



console.log(process.env.API_KEY);
secret = process.env.SECRET;

// userSchema.plugin(encrypt,{secret:secret, encryptedFields:["password"]});


const User = mongoose.model("User",userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});


passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",

  },
  function(accessToken, refreshToken, profile,cb) {
    console.log({"Profile":profile});
  

    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_SECRET,
    callbackURL: "http://localhost:3000/auth/github/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
  	console.log(profile);
    User.findOrCreate({ githubId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


passport.use(new MicrosoftStrategy({
        clientID: process.env.MS_CLIENT_ID,
        clientSecret: process.env.VALUE,
        callbackURL: "http://localhost:3000/auth/microsoft/secrets",
        scope: ['user.read']
      },
      function(accessToken, refreshToken, profile, done) {
        User.findOrCreate({ MS_Id: profile.id }, function (err, user) {
          return done(err, user);
        });
      }
    ));



// passport.use(new LinkedInStrategy({
//     consumerKey: LINKEDIN_API_KEY,
//     consumerSecret: LINKEDIN_SECRET_KEY,
//     callbackURL: "http://localhost:3000/auth/linkedin/secrets"
//   },
//   function(token, tokenSecret, profile, done) {
//     User.findOrCreate({ linkedinId: profile.id }, function (err, user) {
//       return done(err, user);
//     });
//   }
// ));




app.get("/",function(req,res){
	res.render("home");
});

app.get("/login",function(req,res){
	res.render("login");
});

app.get("/register",function(req,res){
	res.render("register");
});

app.get("/secrets",function(req,res){
	if(req.isAuthenticated()){
		res.render("secrets");
	}
	else{
		res.redirect("/login");
	}
});

app.get("/logout",function(req,res){
	req.logout();
	res.redirect("/");
});

app.post("/register",function(req,res){
	
	User.register({username: req.body.username}, req.body.password, function(err,user){
		if(err){
			console.log(err);
			res.redirect("/register");
		}
		else{
			passport.authenticate("local")(req,res,function(){
				res.redirect("/secrets");
			})
		}
	});
});


app.post("/login",function(req,res){
	const user = new User({
		username:req.body.username,
		password:req.body.password
	});
	req.login(user,function(err){
		if(err){
			console.log(err);
			res.redirect("/login");
		}
		else{
			passport.authenticate("local")(req,res,function(){
				res.redirect("/secrets");
			});
		}
	});
});


app.get("/auth/google",
  passport.authenticate("google", {scope: [
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/userinfo.email'
] })
);

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login"}),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
});


app.get('/auth/microsoft',
      passport.authenticate('microsoft'));

    app.get('/auth/microsoft/secrets', 
      passport.authenticate('microsoft', { failureRedirect: '/login' }),
      function(req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
      });


app.get('/auth/github',
  passport.authenticate('github'));

app.get('/auth/github/secrets', 
  passport.authenticate('github', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });



app.get('/auth/linkedin',
  passport.authenticate('linkedin'));

app.get('/auth/linkedin/secrets', 
  passport.authenticate('linkedin', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });




app.listen(3000,function(){
	console.log("3000 port running");
});