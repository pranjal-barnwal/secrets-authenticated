//:!    Ciphering -> Hashing -> Salting ->  Cookies & Sessions  ->  OAuth(Open Authorisation)  

require('dotenv').config();
// console.log(process.env);        //:?    just to check DotEnv module is linked    
//:/    inside  '.env' file in root directory, we keep all the environment varialbes     

const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');


/// Level 2: for Ciphering the password for better security

/// Level 2: for Ciphering the password for better security
// const encrypt = require('mongoose-encryption');

/// Level 3: Ciphered text can still be decrypted, so better way is HASHING      
// const md5 = require('md5');
// console.log(md5('message'));     //* just to test 'md5' is loaded

/// Level 4: Bcrypt is better than 'Mongoose-encryption' and 'md5' as it uses Salting additionally
// const bcrypt = require('bcrypt');
// const saltRounds = 8;

/// Level 5: Cookies & Sessions are better than previous before
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');       // we dont need to include 'passport-local' bcoz its a dependency to 'passport-local-mongoose', which is already incorporated

/// Level 6: O-Auth: with Google
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const findOrCreatePlugin = require('mongoose-findorcreate');




const port = 3000;
const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));


//* we need to set session before connecting to mongoDB right here
app.use(session({
    secret: 'My super secret code.',
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());


mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// const secret = 'Thisisourlittlesecret.';      //? this String will be used to encrypt        // for security during online hosting, we stored inside .env

/// to be used in Ciphering     // not needed in Hashing part
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password']});       //:*   must be used before defining Mongo Collection


const User = mongoose.model('User', userSchema);

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

/// for all purposes 
passport.serializeUser(function (user, done) {
    done(null, user);
});

passport.deserializeUser(function (user, done) {
    done(null, user);
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
},
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile);
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));



app.get('/', (req, res) => {
    res.render('home');
});


app.get('/auth/google', passport.authenticate('google', {
    scope: ['profile']
})); 


app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
    });


app.get('/register', (req, res) => {
    res.render('register');
});


app.get('/login', (req, res) => {
    res.render('login');
});


app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            console.log('Error occured:', err);
        }
        else {
            res.redirect('/');
        }
    });
});


app.get('/submit', (req, res) => {
    if (req.isAuthenticated()) {
        res.render('submit');
    }
    else {
        res.redirect('/login');
    }
});


app.get('/secrets', (req, res) => {
    User.find({'secret': {$ne: null}}, (err, foundUsers) => {
        if(err){
            console.log('Err:', err);
        }
        else if(foundUsers){
            res.render('secrets', {usersWithSecrets: foundUsers});
        }
    });
});



app.post('/register', (req, res) => {
    User.register({ username: req.body.username }, req.body.password, (err, user) => {
        if (err) {
            console.log('Error occured:', err);
            res.redirect('/register');
        }
        else {
            passport.authenticate('local')(req, res, () => {
                res.redirect('/secrets');
            });
        }
    });


    // const hash = bcrypt.hashSync(req.body.password, saltRounds);

    // const newUser = new User({
    //     username: req.body.username,
    //     password: hash
    // });

    // User.findOne({ username: newUser.username }, (err, foundUser) => {
    //     if(err){
    //         console.log('Error occured:', err);
    //     }
    //     else if (foundUser){
    //         console.log('User with same credential already exists. \nTry to login');
    //         res.redirect('/login');
    //     }
    //     else{
    //         console.log('Successfully added the user to the list');
    //         newUser.save();        
    //         res.render('secrets');
    //     }
    // });
});



app.post('/login', (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user, (err) => {
        if (err) {
            console.log('Error occured:', err);
        }
        else {
            passport.authenticate('local')(req, res, () => {
                res.redirect('/secrets');
            });
        }
    });


    // const userEmail = req.body.username;
    // const password = req.body.password;
    // User.findOne({ username: userEmail }, (err, foundUser) => {
    //     if(err){
    //         console.log('Error occured:', err);
    //     }
    //     else if (foundUser){
    //         const hash = bcrypt.hashSync(password, saltRounds);
    //         bcrypt.compare(password, hash, function(err, result) {
    //             if(result === true){
    //                 res.render('secrets');
    //             }
    //             else if(result === true){
    //                 console.log(`Password🔑 didn't match, retry again.`);
    //                 console.log(foundUser.password);
    //                 console.log(hash);
    //             }
    //             else{
    //                 console.log('Some error occured while comparing Hashes');
    //             }
    //         });
    //     }
    //     else{
    //         console.log('User not found, recheck your email📧');
    //     }
    // })
});

app.post('/submit', (req, res) => {
    const submittedSecret = req.body.secret;
    console.log(req.user.id);

    User.findById(req.user.id, (err, foundUser) => {
        if(err){
            console.log('Error:', err);
        }
        else if (foundUser){
            foundUser.secret = submittedSecret;
            foundUser.save(() => {
                res.redirect('/secrets');
            });
        }
        else{
            
        }
    })
});



app.listen(port, () => {
    console.log('Server running on port: ' + port);
})