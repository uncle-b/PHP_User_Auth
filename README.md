# php Auth
Easy Basic PHP Authentication library that can be integrated in any PHP environment. The authentication logic is based on the use of JSON Web Tokens (JWT). The library does not store user passwords but only hashed values that cannot be reversed to produce the user password. Therefore password recovery is not possible, but passwords can be reset. User email addresses are encrypted before storing them. User names and user Id's are not encrypted for practical reasons. The login flow implements Multi Factor Authentication by sending a 4 digit code to the users email address before granting access. Other MFA implementations are not currently supported.

# Licence
MIT

# Requirements
- PHP
- Composer (bypass possible)
- MySQL

# Installation

1. **Clone the repository:**

Clone the repository to your document root 

```bash
git clone https://codeberg.org/uncle-b/PHP_User_Auth.git
```
2. **Run the setup script:**

visit localhost/Auth/setupScript.php in your browser. 'localhost' can of course be replaced by your own domain if that is more convenient. If you follow the instructions, this will automatically create a dedicated SQL database, database user and accounts table required for the authentication logic to work.

3. **Install dependencies:**

When the setup script has finished, the last step is to install the external PHPMailer libary that is required for sending system emails. Using composer you can do this by typing below command in your terminal:

```bash
composer update
```
If you do not have composer installed, you can also manually create a vendor/phpmailer/phpmailer directory in your document root and copy the PHPMailer repository there.

4. **Testing**:

explore the basic functionality with the basic template dialogs in the Auth/dialogs folder:
- 'SignUp.php' provides a basic user registration flow.
- 'SignIn.php' provides the basic login functionality.
- 'passwordForgot' provides basic password recovery.

# Documentation

## Basic Usage:
At the backend, any PHP Script requiring authentication should include the Auth2.php file. This will automatically produce a $auth object containing status indicators and authentication methods. After including the Auth2.php run the $auth->authenticateRequest() method to authenticate the client request.

In code this looks like:
```bash
    include Auth2.php;
    $authentic = $auth->authenticateRequest();
    if($authentic){
        $userId = $auth->userId;
        $userName = $auth->username;
        echo "Request authorized for user $userName with user Id $userId.";
    } else {
        echo "unauthorized request.";
    }
```

At the font end, every request that requires authorization should carry a valid JWT token in a httponly cookie named 'X-AUTH-KEY'. This is automatically set after a successfull login and automatically returned to the server with every client request from a browser.

Secondly, each request should carry a header named 'HTTP_X_AUTH_BODY_TOKEN' carrying the bodyToken returned as the value of a hidden input named 'bodyToken' after a successfull login.

In Javascript this would look like:

```bash
async function authFetchJSON(url, request, bodyToken, method="POST"){
    return fetch(url, {
        method: method,
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Auth-Body-Token': bodyToken,
        },
        body: JSON.stringify(request),
      }).then(async (response)=>{
        
        return response.json();
        
      });
}
```
Note that the above function is included in Auth/js/fetch.js
Please see the examples folder for a working example single-page application.

## Auth class methods

### randomString($n)
Produces a random string of $n charachters. 

**Parameters**
- $n (Integer): produced string length.

**Return value**
- String: Random string of $n charachters.


### userExists($user)
Checks if a given username already exists. 

**Parameters**
- $user (String): user name to check for existence. 

**Return value**
- Boolean: true for existing user name, false for non existing user name.


## validatePassword($pwd)

Checks password for minimal requirements, being:
- Minimum length of 8 charachters
- At least one capital letter.
- At least one small letter.
- At least one number.
- At least one special charachter.

**Parameters**
- $pwd (String): password to check.

**Return value**
- Boolean: true for passing requirements checks, false for not passing.


## validateEmail($eml)
Checks email address for correct composition.

**Parameters**
- $eml (String): email address to check.

**Return value**
- Boolean: true for passing requirements checks, false for not passing.


## encryptDataArray($dataArray)
Encrypts the values of a one dimensional associative array to encrypted strings. An "nonce" key is added to the data array and must be stored with the encrypted data for decryption.

**Parameters**
- $dataArray (Array): one dimensional assiciative array.

**Return value**
- Associative array: Array containing the original key/value pairs, but with encrypted values. One additional key/value pair named "nonce" is added to the array and must be saved with the encrypted data for later decryption. 


## decryptDataArray($dataArray)
Decrypts the values of a one dimensional associative array to their original values.

**Parameters**
- $dataArray (Array): one dimensional associative array. Must include the corresponding "nonce" key/value pair as produced by the encryptDataArray method. 

**Return value**
- Associative array: Array containing the decrypted key/value pairs.


## createUser($usr, $eml, $psw, [$validationURL])
Creates a user record in the database with the specified username, email address and password.

**Parameters**
- $usr (String): Username 
- $eml (String): Email address
- $psw (String): password
- $validationURL (String, optional): alternative url to complete the email validation process. Defaults to dialogs/emailValidate.php if not set.

**Return value**
- Boolean: True for success, False for failure.

**Remarks**
- This function uses the template emails/emailValidation.php for the email sent to the user for validation. You can edit this template to your own preferences.


## verifyAccount($id, $key)
Part of the email address validtaion process. This will check the verification key sent to the user by email against the new created user account.

**Parameters**
- $id (integer): userId
- $key (integer): 4-figures validation code.

**Return value**
- Boolean: True on success, False on failure.


## signIn($usr, $psw)
Authorizes user, based on username and password combination and MFA verification by email.

**Parameters**
- $usr (string): user name 
- $psw (string): password

**Return value**
- Associative array (Array): Array of the following key/value pairs:
  - error (Boolean): false means no errors.
  - message (String): success message or error description. 
  - token (String): JWT token to be set as httponly cookie.
  - loginId (String): loginId associated to the current session.
  - bodyToken (String): Body token to be included with request body te verify request origin.

If error is true, only the error and message fields are included.


## testEmail($mailto, [$displayName])
Exists for testing purposes only. Will send one email to the specified email address and echo debug information.

**Parameters**
- $mailto (String): destination email address.
- $displayName (String, optional): Sender name to be displayed email header.

**Return value**
- None.


## sendEmail($mailto, $subject, $message, [$altMessage], [$displayName])
Will send one email to the specified email address.

**Parameters**
- $mailto (String): destination email address.
- $subject (String): email subject.
- $message (String): html email body.
- $altMessage (String, optional): non-html alternative email body.
- $displayName (String, optional): Sender name to be displayed email header.

**Return value**
- None.


## requestPasswordReset($username, [$resetURL])
Will send one email to the registered email address of the specified user to initiate the password reset process. 

**Parameters**
- $username (String): user requesting the reset.
- $resetURL (String, optional): url to link to in the reset email. Defaults to dialogs/passwordReset.php.

**Return value**
- Boolean: Always returns true.


## getUserByEmail($email)
Returns the first authenticated user associated to the specified email address. 

**Parameters**
- $email (String): user requesting the reset.

**Return value**
- Array or Boolean: Associative array containing the user details or false if no user is found.


## authenticateRequest()
Authenticate a http request, based on the provided 'X-AUTH-KEY' cookie (containing the JWT token) and the 'HTTP-X-AUTH-BODY-TOKEN' header (containing the body token).

**Parameters**
- None. (Will read request headers directly).

**Return value**
- Boolean: True for authenticated request. False for failed authentication.

With a succesfull authentication, the $auth->userId and $auth->userName are filled with the corresponding values for future reference.


## initiateMFA($username, $password)
Start the MFA procedure if a correct combination of username and password are provided. Will send one email with a verification code to the registered email address of the given user.

**Parameters**
- $username (String): User name.
- $password (string): User password.

**Return value**
- Associative array (Array): Array of the following key/value pairs:
  - error (Boolean): false means no errors.
  - message (String): success message or error description. 
  - userId (Integer): user Id
  - username (String): user name

On error, only the error and message fields are included.


## verifyMFA($userId, $code, $password, $username)
Complete the MFA procedure by checking the userId against the generated MFA code and provided username and password.

**Parameters**
- $userId (Integer): user Id.
- $code (Integer): MFA Code.
- $username (String): User name.
- $password (string): User password.

**Return value**
- Associative array (Array): Array of the following key/value pairs:
  - error (Boolean): false means no errors.
  - message (String): success message or error description. 

## resetPassword($userId, $resetToken, $newPassword, $newPasswordRepeat)
Complete the password reset procedure.

**Parameters**
- $userId (Integer): user Id.
- $resetToken (String): Token to validate reset request.
- $newPassword (String): New password.
- $newPasswordRepeat (string): New password. 

**Return value**
- Associative array (Array): Array of the following key/value pairs:
  - error (Boolean): false means no errors.
  - message (String): success message or error description. 


# Other Repos That You Might Be Interested In
- [PHP Mailer](https://github.com/phpmailer/phpmailer) - Library for SMTP emailing in PHP.