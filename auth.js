const router = require('express').Router();
const bcrypt = require('bcryptjs');
const {registerValidation, loginValidation, socialLoginValidation} = require('../utils/validation');
const jwt = require('jsonwebtoken');
const User = require('../model/User');

const createAndAssignJWT = (user, res) => {
    // Create and assign JWT for this session
    const token = jwt.sign({_id: user._id}, process.env.TOKEN_SECRET, {expiresIn:'30d'});
    res.status(200).header('auth-token-mazefm', token).send(
        {
            id: user._id,
            jwt: token,
            email: user.email,
            name: user.name,
            img: user.img
        });
}
const registerUser = async(req, res, socialSignIn) => {

    // hash the password
    const salt = await bcrypt.genSalt(10);
    var hashedPassword = null;
    if(req.body.password) {
        hashedPassword = await bcrypt.hash(req.body.password, salt);
    }
    
    // create a new user.
    const user = new User({
        email: req.body.email,
        password: hashedPassword,
        name: req.body.name,
        img: req.body.img
    });

    try {
        const savedUser = await user.save();
        if(socialSignIn === false) {
            res.status(201).send({user: savedUser._id});
        }
        else {
            createAndAssignJWT(savedUser, res);
        }
    }
    catch(err) {
        res.status(400).send(err);
    }
}

// Register ROUTE
router.post('/register', async (req, res) => {
    
    // Validate the data before making a user
    const {error} = registerValidation(req.body);

    if(error) {
        return res.status(400).send(error.details[0].message);
    }

    // check if user already exists in the database
    const userExist = await User.findOne({email: req.body.email});
    if(userExist) {
        return res.status(400).send('User already exists!');
    }

    registerUser(req, res, false);
});

// Login ROUTE -- used for classic MazeFM App login method
router.post('/login', async (req, res) => {
    
    // Validate the data before we login the user.
    const {error} = loginValidation(req.body);
    if(error) return res.status(400).send(error.details[0].message);

    // checking if the email exists in the database
    const user = await User.findOne({email: req.body.email});
    if(!user) {
        return res.status(400).send('Email doesn\'t exist!');
    }

    // Password is correct
    const validPass = await bcrypt.compare(req.body.password, user.password);
    if(!validPass) return res.status(400).send('Invalid Password');

    // Create and assign JWT for this session
    createAndAssignJWT(user, res);

});

router.post('/social-auth', async(req, res) => {

    // Validate the data before we login the user.
    const {error} = socialLoginValidation(req.body);

    // check if email exists in the database -- that means user already signed up with facebook
    const user = await User.findOne({email: req.body.email});

    // if not, register user.
    if(!user) {
        registerUser(req, res, true);
        return;
    }

    // social media picture may differ from login to login.
    // so update it.
    await User.updateOne({_id: user._id}, {
        img: req.body.img
    });

    // create and assign JWT for this session.
    createAndAssignJWT(user, res);
});

module.exports = router;