require("ejs");
require('dotenv').config();
const PORT = process.env.PORT || 3000;
const express = require("express");
const bodyParser = require("body-parser");
const app = express();
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose"); 
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');


app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
secret: process.env.SESSION_SECRET, //! This is the secret used to sign the session ID cookie.
resave: false,
saveUninitialized: false
}));

app.use(passport.initialize()); 
app.use(passport.session()); 


//#---Local Database Connected---//
// mongoose.connect("mongodb://127.0.0.1:27017/userDB", { useNewUrlParser: true }, mongoose.set('strictQuery', false));

//#----MongoDB ATLAS Connection----//
mongoose.connect(process.env.ATLAS_URL, { useNewUrlParser: true}, {useUnifiedTopology: true}, mongoose.set('strictQuery', false));

//#---Schema---//
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String, //! To store the ID that is receieved from Google
  secret: String //! To store the secret posted by user
});

//#---Plugin---//
userSchema.plugin(passportLocalMongoose); 
userSchema.plugin(findOrCreate);


//#---Model---//
const User = new mongoose.model("User", userSchema);

//#--- LocalStrategy---//
passport.use(User.createStrategy());

//#---USER Serialization & De-Serialization---//
passport.serializeUser(function(user, cb) {
process.nextTick(function() {
  cb(null, { id: user.id, username: user.username, name: user.name });
});
});
passport.deserializeUser(function(user, cb) {
process.nextTick(function() {
  return cb(null, user);
});
});


//#---Google Oauth2.0 config and Strategy---#//
passport.use(new GoogleStrategy({
clientID: process.env.CLIENT_ID,
clientSecret: process.env.CLIENT_SECRET,
callbackURL: "https://secrets-mzso.onrender.com/auth/google/secrets",
userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" //! From GitHub Issues because of G+ Deprecation 
},
function(accessToken, refreshToken, profile, cb) {
console.log(profile.id, profile.name);
User.findOrCreate({ googleId: profile.id }, function (err, user) {
  return cb(err, user);
});
}
));

//# GET - /AUTH/GOOGLE
app.get('/auth/google', passport.authenticate("google", { scope: ["profile"] }));
//! This request triggers when user uses the sign up with google on register page

//# GET - /AUTH/GOOGLE/SECRETS
//! this get req is triggered by google when it completes user authentication.
app.get('/auth/google/secrets',  passport.authenticate("google", { failureRedirect: "/login" }), function(req, res) {
  res.redirect('/secrets');
  //! Successful authentication, redirect to secrets.
});


//# GET - /
app.get("/", function (req, res) {
res.render("home");
});


//# GET - LOGIN
app.get("/login", function (req, res) {
if(req.isAuthenticated()){
  res.redirect("/secrets");
} else {
  res.render("login");
}
});


//# GET - REGISTER
app.get("/register", function (req, res) {
res.render("register");
});




//# GET - SECRETS
app.get("/secrets", function(req, res){
User.find({"secret": {$ne: null}}, function(err, foundUsers){ //! {$ne: null} means not null
  if(err){
    console.log(err);
  } else {
    if(foundUsers) {
    //console.log("Cookie that is being sent back: " + req.headers.cookie); //! This logs the cookie that client sents to us with HTTP GET request.
      res.render("secrets", {SecretUsers: foundUsers});
    } else {
      console.log("No secret has been posted yet, check back later or post your secret.");
    }
  }
});
});


//# GET - SUBMIT
app.get("/submit", function(req, res){
if(req.isAuthenticated()){
  res.render("submit");
} else{
  res.render("login");
}
});


//# GET - LOGOUT
app.get("/logout", function(req, res){
  req.logout(function(err) {
    if (err) { 
      console.log(err); 
    } else{
      res.redirect('/');
      console.log("User Logged out and this session ended: " + req.headers.cookie);
    }
  });
  });


//# POST - REGISTER
app.post("/register", function(req, res){
//! Below code is from passport-local-mongoose
User.register({ username: req.body.username }, req.body.password, function(err, user){
  if(err){
    console.log(err);
    res.redirect("/register");
  } else{
    passport.authenticate("local")(req, res, function(){
      console.log("New User Registered: " + req.user.username);
      res.redirect("submit");

    })
  }
})
});

//# POST - LOGIN 
//? Do research on how to give bad credential msg 
app.post("/login", function(req, res){
const user = new User({
  username: req.body.username,
  password: req.body.password
});
//! Below code is from passport.js > concepts > authentication > log in
req.login(user, function(err){
  if(err){
    console.log(err);
  } else {
    passport.authenticate("local")(req, res, function(){
      res.redirect("secrets");
      console.log("Current logged in user: " + req.user.username); 
      // console.log("Cookie that is being Set: " + res.get('set-cookie'));  //! This logs the cookie that is being set by server with the HTTP POST response.
    })
  } 
});
});

//*alternate method found on stackOverflow
// app.post("/login", (req, res) => {
//   passport.authenticate("local")(req, res, function(){
//     res.redirect("secrets");
//   })
// });



//# POST - SUBMIT
app.post("/submit", function(req, res){
const submittedSecret = req.body.secret;
const loggedInUserID = req.user.id;  //! Fetching the logged in user ID from the session that we receive through cookie(session)

User.findById(loggedInUserID, function(err, foundUser){
  if(err){
    console.log(err);
  } else{
    if(foundUser){
      foundUser.secret = submittedSecret;
      foundUser.save(function(){
        res.redirect("secrets");
      })
    }
  };
});
});

//#---Server---//
app.listen(PORT, function () {
console.log("Listening on port " + PORT);
});
