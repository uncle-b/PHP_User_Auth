<!DOCTYPE html>
<html>
    <head>
        <link rel="stylesheet" href="SinglePage.css">
        <script src="validation.js"></script>
        <script src="SinglePage.js"></script>
        <script src="../../Auth/js/fetch.js"></script>
    </head>
    <body>


        <!-------------- Sign Up Page ---------------->

        <div class="page" id="page-sign-up" style="display:none;">
            <h1>Sign up</h1>
            <div id="sign-up-form">
                <label>User name</label>
                <input type="text" id="signup-usr" onkeyup="validateInput()" maxlength="50"/><br/>
                <label>Email address</label>
                <input type="email" id="eml" onkeyup="validateInput()" maxlength="254"/><br/>
                <label>Password</label>
                <input type="password" id="pwd1" onkeyup="validateInput()" maxlength="128"/>
                <button type="button" class="togglePwd" onclick="togglePassword(['pwd1','pwd2']);">&#128065;</button>
                <label>Repeat password</label>
                <input type="password" id="pwd2" onkeyup="validateInput()" maxlength="128"/><br/>
                <label></label>
                <button type="button" id="button-sign-up" onclick="signUp();">Sign up</button><br/>
                <label></label>
                <span class ="errorMsg" id="sign-up-message"></span>
            </div>
        </div>

        <!-------------- Sign Up Success Page ---------------->

        <div class="page" id="page-sign-up-success" style="display:none;">
            <h1>Check your email</h1>
            <div id="sign-up-form">
                Thank you for signing up. We have sent you an email to verify your email address.
            </div>
            
        </div>

        <!-------------- Email Validate Success Page ---------------->

        <div class="page" id="page-email-validate-success" style="display:none;">
            <h1>Email validated</h1>
            <label></label>
            <div style="display: inline-block;">
                Your email address has been validated. You can now sign in.
            </div>
            <label></label>
            <button type="button" onclick="showPage('page-sign-in');">Sign in</button><br/>
        </div>

        <!-------------- Email Validate Failure Page ---------------->

        <div class="page" id="page-email-validate-failed" style="display:none;">
            <h1>Email validation failed</h1>
            <label></label>
            <div style="display: inline-block;">
                Sorry, we could not validate your email address.
            </div>
            <label></label>
            <button type="button" onclick="showPage('page-sign-up');">Sign up</button><br/>
        </div>


        <!-------------- Sign In Page ---------------->

        <div class="page" id="page-sign-in">
            <h1>Sign In</h1>
            <div id="sign-in-form">
                <label>User name</label>
                <input type="text" id="usr" maxlength="50"/><br/>
                <label>Password</label>
                <input type="password" id="psw" maxlength="128"/>
                <button type="button" class="togglePwd" onclick="togglePassword(['psw']);">&#128065;</button><br/>
                <label></label>
                <button type="button" onclick="signIn();">Sign in</button> 
                <label></label>
                <button type="button" onclick="showPage('page-sign-up');">Sign up</button><br/>
                <label></label>
                <button type="button" onclick="showPage('page-password-forgot');" style="margin-top: 10px; background: none; border: none; color: #007bff; cursor: pointer; text-decoration: underline;">Forgot password?</button><br/>
                <label></label>
                <span class ="errorMsg" id="sign-in-message"></span>
            </div>
        </div>

        <!-------------- Forgot Password Page ---------------->

        <div class="page" id="page-password-forgot" style="display:none;">
            <h1>Forgot Password</h1>
            <div id="password-forgot-form">
                <p>Enter your username and we will send a password reset link to your email address.</p>
                <label>User name</label>
                <input type="text" id="forgot-username" maxlength="50"/><br/>
                <label></label>
                <button type="button" id="button-password-forgot" onclick="passwordForgot();">Send Reset Link</button><br/>
                <label></label>
                <button type="button" onclick="showPage('page-sign-in');" style="margin-top: 10px; background: none; border: none; color: #666; cursor: pointer;">Back to Sign In</button><br/>
                <label></label>
                <span class ="errorMsg" id="password-forgot-message"></span>
            </div>
        </div>

        <!-------------- Reset Password Page ---------------->

        <div class="page" id="page-password-reset" style="display:none;">
            <h1>Reset Password</h1>
            <div id="password-reset-form">
                <label>New Password</label>
                <input type="password" id="reset-pwd1" onkeyup="validatePasswordReset()" maxlength="128"/>
                <button type="button" class="togglePwd" onclick="togglePassword(['reset-pwd1','reset-pwd2']);">&#128065;</button>
                <label>Confirm New Password</label>
                <input type="password" id="reset-pwd2" onkeyup="validatePasswordReset()" maxlength="128"/><br/>
                <label></label>
                <button type="button" id="button-password-reset" onclick="passwordReset();" disabled>Reset Password</button><br/>
                <label></label>
                <span class ="errorMsg" id="password-reset-message"></span>
            </div>
        </div>

        <!-------------- Password Reset Success Page ---------------->

        <div class="page" id="page-password-reset-success" style="display:none;">
            <h1>Password Reset</h1>
            <div id="password-reset-success">
                Your password has been reset successfully.
                <br><br>
                <button type="button" onclick="showPage('page-sign-in');">Sign In</button>
            </div>
        </div>

        <!-------------- Complete MFA Page ---------------->

        <div class="page" id="page-mfa-complete" style="display:none;">
            <h1>Multi factor authentication</h1>
            <div id="mfaInput">
                <label for="mfa_code">Verification Code:</label>
                <input type="text" id="mfa_code" name="mfa_code" pattern="[0-9]{6}" maxlength="6" required><br>
                <label></label>
                <input type="checkbox" id="trust-device" /><label style="padding-bottom: .2em;">Trust this device</label><br/>
                <label></label>
                <button type="button" onclick="mfaComplete();">Sign in</button>
            </div>
        </div>

        <!-------------- Content Page ---------------->

        <div class="page" id="page-content" style="display:none;">
            <h1>Content page</h1>
            <label></label>
            <button type="button" onclick="showSecretData();">Show secret data</button>
            <label></label>
            <button type="button" onclick="signOut();">Sign out</button><br/><br/>
            <label></label>
            <div id="secret-content" style="display:inline-block;"></div>
        </div>

        <!-------------- Loading page ---------------->

        <div class="page" id="page-loader" style="display:none;">
            <div id="loader-message" style="text-align:center;"></div><br/>
            <div id="loader" class="loaderContainer">
                <div class="loader"></div>
            </div>
        </div>
        
    </body>
    <script>
        // Set the start page
        let startPage = "page-sign-in";
        pageLoader();
        checkUrlParams();
    </script>
</html>