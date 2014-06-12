##CSRF-User
CSRF-User is a quick and easy CSRF protection middleware for Express that protects all but GET requests. CSRF tokens are tied to an individual user, so only that user can use the token they created, and CSRF tokens will also expire after a configurable timeout.
Its only dependcy is the crypto module.


####Installation
    npm install csrf-user

####Usage
######1. Enable cookies and sessions in express
    app.use(cookieParser()); //requires cookie-parser package in Express 4.x+
    app.use(session({secret: 'Your Session Secret'}));
    
######2. Call the middleware
      app.use(csrf('Your CSRF Secret', 'username'));
There are four arguments that can be passed, to csrf(), but only first two are required.

      csrf(secret, username, [sessionVar], [timeout]);

* secret: A unique secret key to use for hashing the CSRF token.
* usernameVar: The session variable (req.session.usernameVar) where the curren't user's username is stored.
* sessionVar: (default='signed') The sesssion variable (req.session.sessionVar) to save the CSRF token in. Use this to inject the token into your app.
* timeout: (default = 60) Number of minutes after which CSRF token should be invalidated.

######3. Inject the token into your app
Inject the token into your HTML such that you can set it as a header in your POST, PUT, and DELETE requests.

For example:

    <input type="hidden" id="token" value="<% signed %>" />
Where <% signed %> gets replaced by your CSRF token (stored in your session as whatever you set sessionVa to).

######4. Set the X-CSRF-Token header
Ensure that any POST, PUT, or DELETE requests have the X-CSRF-Token header set to the token value.

Example using jQuery:

    $(document).bind("ajaxSend", function(elm, xhr, s){
	    if(s.type == "POST" || s.type == "PUT" || s.type == "DELETE"){
		    xhr.setRequestHeader('X-CSRF-Token', $('#token').val());
    	}
    });
      

That's it! Your application is now protected against CSRF. If a POST, PUT, or DELETE comes through with any of the following:

* No CSRF token
* A valid CSRF token generated by another User
* An expired CSRF token

The server will throw an 403 response with the message '403: Forbidden'.

csrf-user is wtten by Jonah Hirsch
