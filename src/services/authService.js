const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const userService = require('../services/userService');
const AppError = require('../errors/appError');
const config = require('../config');

const login = async(email, password)=> {

    //Validacion en email
    try{
        const user = await userService.findByEmail(email);

        if(!user){
            throw new AppError('Authentication failed! Email / Password is not correct.',400)
        }
        //Validacion del enable

        if(!user.enable){
            throw new AppError('Authentication failed! User disabled.',400)
        }

        //Validacion de password
        const validPassword = await bcrypt.compare(password, user.password);

        if(!validPassword){
            throw new AppError('Authentication failed! Email / Password is not correct.',400)
        }

        //Generar JWT
        const token = _encrypt(user._id);

        return{
            token,
            user: user.name,
            role: user.role
        };  

    }catch(error){
        throw error;
    }
}

_encrypt = (id) =>{
    return jwt.sign({id}, config.auth.secret, { expiresIn: config.auth.ttl });
};

module.exports = {
    login
};