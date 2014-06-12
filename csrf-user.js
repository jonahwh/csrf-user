var crypto = require('crypto');

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
        }else if(req.method == "POST" || req.method == "PUT" || req.method == "DELETE"){
            var isok = false;
            var signed = req.get('x-csrf-token');
            if(undefined == signed) signed = req.body.token;
            var parts = signed.split('-');
            if(parts.length == 2){
                var token   = parts[0];
                var hash    = parts[1];
            }
            var tokenParts = token.split('.');
            if(parseInt(tokenParts[1])+(timeout*60*1000) >= Date.now() && hash === crypto.createHmac('sha1', secret).update(token).digest('hex')){
                isok = true;
            }
            if(!isok){
                return res.send('403: Forbidden', 403);
            }
        }
        next();
    }
};


function toHex(str) {
    var hex = '';
    for(var i=0;i<str.length;i++) {
        hex += ''+str.charCodeAt(i).toString(16);
    }
    return hex;
}