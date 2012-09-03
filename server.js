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
	// For now, don't bother persisting information about the user. Simply set
	// a flag so the application can grant access to recognized users.
	done(null, { id: id });
});

function authorize(isRecognized, id, done) {
	if (isRecognized) {
		return done(null, { id: id, isRecognized: true });
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

		authorize(isRecognized, id, done);

	}
));
passport.use(new GoogleStrategy({
		clientID: CREDS.oauth.google.key,
		clientSecret: CREDS.oauth.google.secret,
		callbackURL: "http://localhost:4444/auth/google/callback"
	},
	function(accessToken, refreshToken, profile, done) {

		// profile.emails is an array with the following format:
		// [ { value: "a@b.com" }, { value: "c@d.com" }, ... ]
		// So _.pluck out the e-mail addresses themselves.
		var emailAddresses = _.pluck(profile.emails, "value");
		var ids = _.intersection(CREDS.oauth.google.ids, emailAddresses);
		var id = ids[0];
		var isRecognized = (id !== undefined);

		authorize(isRecognized, id, done);
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

// Simple Express middleware to redirect unauthorized users to the site index
var redirectUnauthorized = function(req, res, next) {
	// Certain pages should be accessible to anyone, namely: the index
	// (login) page and the authorization pages
	if (req.path === "/" || /^\/auth\//.test(req.path) ||
		// All other pages should only be served to users that have
		// properly authenticated
		(req.session && req.session.passport && req.session.passport.user)) {
		next();

	// In any other case, serve the index page
	} else {
		res.redirect("/");
		next("Unauthorized");
	}
};

app.configure(function() {
	app.use(express.bodyParser());
	app.use(express.cookieParser());
	app.use(express.session({ store: store, secret: sessionSecret }));
	app.use(passport.initialize());
	app.use(passport.session());
	app.use(redirectUnauthorized);
});

// simulate a socket connection handler. In this case, only the raw "cookie"
// header will be available. Attempt to parse it according to the server's
// session secret to enable it was not tampered with by the client.
function simulateSocket(cookie) {

	var fakeReq = { headers: { cookie: cookie } };

	sioCookieParser(fakeReq, {}, function(err) {
		var sessionId = fakeReq.signedCookies["connect.sid"];
		store.get(sessionId, function(err, data) {
			if (!data || !data.passport || !data.passport.user) {
				console.log("Rejecting this 'socket'.");
			} else {
				console.log("This 'socket' is authorized to broadcast!");
			}
		});
	});
}

app.get("/", function(req, res) {
	var htmlStrs = ["Hello, world!"];

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

// This endpoint is only accessible by authenticated users
app.get("/authonly", function(req, res) {
	res.send("Authorized personell only!");
});

app.get("/auth/twitter", passport.authenticate("twitter"));
app.get("/auth/twitter/callback",
	passport.authenticate("twitter", {
		successRedirect: "/",
		failureRedirect: "/"
	}));

app.get("/auth/google", passport.authenticate("google", {
	scope: [
		"https://www.googleapis.com/auth/userinfo.profile",
		"https://www.googleapis.com/auth/userinfo.email"
	]}));
app.get("/auth/google/callback",
	passport.authenticate("google", {
		successRedirect: "/",
		failureRedirect: "/"
	}));

app.get("/logout", function(req, res) {
	req.logOut();
	res.redirect("/");
});

http.createServer(app).listen(4444);
https.createServer(CREDS.ssl, app).listen(4445);
