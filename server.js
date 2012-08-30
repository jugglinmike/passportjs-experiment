var express = require("express");
var passport = require("passport");
var _ = require("underscore");

//var OAuthStrategy = require("passport-oauth").OAuthStrategy;
var TwitterStrategy = require("passport-twitter").Strategy;
var GoogleStrategy = require("passport-google-oauth").OAuth2Strategy;

var TwitterCreds = require("./credentials/twitter.json");
var GoogleCreds = require("./credentials/google.json");

passport.serializeUser(function(user, done) {
	done(null, user.id);
});
passport.deserializeUser(function(id, done) {
	done(null, { id: id });
	//User.findOne(id, function (err, user) {
	//	done(err, user);
	//});
});

passport.use(new TwitterStrategy({
		consumerKey: TwitterCreds.key,
		consumerSecret: TwitterCreds.secret,
		callbackURL: "http://localhost:4444/auth/twitter/callback"
	},
	function(token, tokenSecret, profile, done) {

		var id = profile.username;
		var isRecognized = TwitterCreds.ids.indexOf(id) > -1;

		if (isRecognized) {
			return done(null, { id: "mike-twitter" });
		} else {
			return done("Not recognized");
		}
	}
));
passport.use(new GoogleStrategy({
		clientID: GoogleCreds.key,
		clientSecret: GoogleCreds.secret,
		callbackURL: "http://localhost:4444/auth/google/callback"
	},
	function(accessToken, refreshToken, profile, done) {

		var emailAddresses = _.pluck(profile.emails, "value");
		var isRecognized = _.intersection(GoogleCreds.ids, emailAddresses).length > 0;

		if (isRecognized) {
			return done(null, { id: "mike-google" });
		} else {
			return done("Not recognized");
		}
	}
));

var app = express.createServer();
app.configure(function() {
	app.use(express.cookieParser());
	app.use(express.bodyParser());
	app.use(express.session({ secret: "This is a secret" }));
	app.use(passport.initialize());
	app.use(passport.session());
});

app.get("/", function(req, res) {
	var htmlStrs = ["Hello, world!"];

	if (req.user) {
		htmlStrs.push(JSON.stringify(req.user));
		htmlStrs.push("<a href='/logout'>Sign out</a>");
	} else {
		htmlStrs.push("<a href='/auth/twitter'>Sign in with Twitter</a>");
		htmlStrs.push("<a href='/auth/google'>Sign in with Google</a>");
	}

	res.send(htmlStrs.join("<br />"));
});

app.get("/auth/twitter", passport.authenticate("twitter"));
app.get("/auth/twitter/callback",
	passport.authenticate("twitter", {
		successRedirect: "/",
		failureRedirect: "/login"
	}));

app.get("/auth/google", passport.authenticate("google", {
	scope: [
		"https://www.googleapis.com/auth/userinfo.profile",
		"https://www.googleapis.com/auth/userinfo.email"
	]}));
app.get("/auth/google/callback",
	passport.authenticate("google", {
		successRedirect: "/",
		failureRedirect: "/login"
	}));

app.get("/login", passport.authenticate("twitter"), function(req, res) {
	res.send("Signed in!");
});
app.get("/logout", function(req, res) {
	req.logOut();
	res.redirect("/");
});

app.listen(4444);
