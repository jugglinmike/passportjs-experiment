var fs = require("fs");
var http = require("http");
var https = require("https");
var express = require("express");
var RedisStore = require("connect-redis")(express);
var passport = require("passport");
var _ = require("underscore");

var TwitterStrategy = require("passport-twitter").Strategy;
var GoogleStrategy = require("passport-google-oauth").OAuth2Strategy;

// Credentials, stored in non-version-controlled files
var CREDS = {
	oauth: {
		twitter: require("./credentials/oauth/twitter.json"),
		google: require("./credentials/oauth/google.json")
	},
	ssl: {
		key: fs.readFileSync("./credentials/ssl/privatekey.pem").toString(),
		cert: fs.readFileSync("./credentials/ssl/certificate.pem").toString()
	}
};

passport.serializeUser(function(user, done) {
	done(null, user.id);
});
passport.deserializeUser(function(id, done) {
	done(null, { id: id });
	//User.findOne(id, function (err, user) {
	//	done(err, user);
	//});
});

function authorize(isRecognized, token, tokenSecret, done) {
	if (isRecognized) {
		return done(null, { id: "mike-twitter" });
	} else {
		return done("Not recognized");
	}
}

passport.use(new TwitterStrategy({
		consumerKey: CREDS.oauth.twitter.key,
		consumerSecret: CREDS.oauth.twitter.secret,
		callbackURL: "http://localhost:4444/auth/twitter/callback"
	},
	function(token, tokenSecret, profile, done) {

		var id = profile.username;
		var isRecognized = CREDS.oauth.twitter.ids.indexOf(id) > -1;

		authorize(isRecognized, token, tokenSecret, done);

	}
));
passport.use(new GoogleStrategy({
		clientID: CREDS.oauth.google.key,
		clientSecret: CREDS.oauth.google.secret,
		callbackURL: "http://localhost:4444/auth/google/callback"
	},
	function(accessToken, refreshToken, profile, done) {

		var emailAddresses = _.pluck(profile.emails, "value");
		var isRecognized = _.intersection(CREDS.oauth.google.ids, emailAddresses).length > 0;

		authorize(isRecognized, accessToken, refreshToken, done);
	}
));

var app = express();
// Dynamically generating a secret in this way means one less file will have to
// be managed outside of the repository. The drawback is that, in the event of
// a server re-start, all authenticated users will be kicked and need to re-
// authenticate.
var sessionSecret = "This is a secret." + Math.random();;
var sioCookieParser = express.cookieParser(sessionSecret);
var store = new RedisStore();
app.configure(function() {
	app.use(express.bodyParser());
	app.use(express.cookieParser());
	app.use(express.session({ store: store, secret: sessionSecret }));
	app.use(passport.initialize());
	app.use(passport.session());
});

// simulate a socket connection handler. In this case, only the raw "cookie"
// header will be available. Attempt to parse it according to the server's
// session secret to enable it was not tampered with by the client.
function simulateSocket(cookie) {

	var fakeReq = { headers: { cookie: cookie } };

	sioCookieParser(fakeReq, {}, function(err) {
		var sessionId = fakeReq.signedCookies["connect.sid"];
		store.get(sessionId, function(err, data) {
			console.log("Session data, retrieved by 'socket'", data);
		});
	});
}

app.get("/", function(req, res) {
	var htmlStrs = ["Hello, world!"];

	req.session.customCounter = (req.session.customCounter || 0) + 1;

	simulateSocket(req.headers.cookie);

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

http.createServer(app).listen(4444);
https.createServer(CREDS.ssl, app).listen(4445);
