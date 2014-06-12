var crypto      = require('crypto'),
    formidable  = require('formidable'),
    _           = require('underscore');

module.exports = function(secret, usernameVar, sessionVar, timeout){
    return function(req, res, next){

        if(undefined == secret) throw("csrf-user: Secret is required!");
        if(undefined == usernameVar) throw("csrf-user: Username is required!");
        if(undefined == sessionVar) sessionVar = 'signed';
        if(undefined == timeout) timeout = 60;

        if(req.method == "GET"){
            var token   = toHex(req.session[usernameVar])+'.'+Date.now()+'.'+Math.random().toString(36).substring(7);
            var hash    = crypto.createHmac('sha1', secret).update(token).digest('hex');
            req.session[sessionVar] = _.escape(token+'-'+hash);
            next();
        }else if(req.method == "POST" || req.method == "PUT" || req.method == "DELETE"){
            var signed = req.get('x-csrf-token');
            if(undefined == signed){
                var form = new formidable.IncomingForm();
                form.parse(req, function(err, fields, files){
                    if(err) throw(err);
                    req.session.form = {fields: fields, files: files};
                    signed = fields.token;
                    if(!verify(signed, timeout, secret)){
                        res.send(403);
                    }else{
                        next();
                    }
                });
            }else{
                if(!verify(signed, timeout, secret)){
                    res.send(403);
                }else{
                    next();
                }
            }
        }
    }
};

function verify(signed, timeout, secret){
    var parts = signed.split('-');
    if(parts.length == 2){
        var token   = parts[0];
        var hash    = parts[1];
    }
    var tokenParts = token.split('.');
    return parseInt(tokenParts[1])+(timeout*60*1000) >= Date.now() && hash === crypto.createHmac('sha1', secret).update(token).digest('hex');
}

function toHex(str) {
    var hex = '';
    for(var i=0;i<str.length;i++) {
        hex += ''+str.charCodeAt(i).toString(16);
    }
    return hex;
}