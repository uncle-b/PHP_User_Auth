<?php
include "../Auth2.php";

// Start session for CSRF protection
$auth->startSession();

$requestData = $auth->getRequestData();
$isJson = $auth->isJsonRequest();

// Handle MFA verification
if(isset($requestData["mfa_code"]) && isset($requestData["userId"]) && isset($requestData["username"]) && isset($requestData["password"])){
    $userId = $requestData["userId"];
    $username = $requestData["username"];
    $password = $requestData["password"];
    $mfaCode = $requestData["mfa_code"];
    
    $csrfToken = isset($requestData["csrf_token"]) ? $requestData["csrf_token"] : null;
    try{
        $result = $auth->verifyMFA($userId, $mfaCode, $password, $username, $csrfToken);
        if($result['error'] === false && isset($result['token'])){
            // MFA verified and login complete
            $cookie_name = "X_AUTH_KEY";
            $cookie_value = $result['token'];

            $https=false;
            if($auth->isSecure()){
                $https=true;
            };


            $arr_cookie_options = array (
                'expires' => 0, 
                'path' => '/', 
                'domain' => '.'.$_SERVER['SERVER_NAME'], // leading dot for compatibility or use subdomain
                'secure' => $https,     // or false
                'httponly' => true,    // or false
                'samesite' => 'Strict' // None || Lax  || Strict
                );

            //setcookie($cookie_name, $cookie_value, 0, "/", $_SERVER['SERVER_NAME'], $https, true); 
            setcookie($cookie_name, $cookie_value, $arr_cookie_options); 

            $bodyToken = $result['bodyToken'];
            
            // For JSON requests, return JSON response
            if($isJson) {
                $auth->jsonResponse([
                    'error' => false,
                    'message' => 'Login successful',
                    'token' => $result['token'],
                    'bodyToken' => $bodyToken
                ]);
            }
            
            ?>
            <!DOCTYPE html>
            <html>
                <head>
                    <link rel="stylesheet" href="dialogs.css">
                    <script src="/Auth/js/fetch.js"></script>
                    <script>
                        async function signOut(){
                            var method = "POST";
                            var requestUrl = "/Auth/api/SignOut.php";
                            var bodyToken = document.getElementById("bodyToken").value;
                            var request = {
                                onAllAccounts: false,
                                redirectUrl: "/"
                            }
                            
                            try {
                                var res = await authFetchJSON(requestUrl, request, bodyToken);
                                if(res.error === false){
                                    window.location.href = "/";
                                } else {
                                    console.log(res.message);
                                }
                                
                            } catch (error) {
                                console.error("Sign out failed:", error);
                            }
                        }

                    </script>
                </head>
                <body>
                    <div class="container">
                        <h1>Login successful</h1>
                        <input id='bodyToken' type='hidden' value='<?php echo $bodyToken; ?>' name='bodyToken'/>
                        <p>
                            Login succeeded. A httponly cookie with an authentication key has been set. This will be automatically sent back to the server with every request.
                        </p>
                        <p>
                            Besides that, a hidden input, named 'bodyToken' is included in this page. The value of that should be returned with every request by setting a http header named 'X-Auth-Body-Token' containing this value.
                        </p>
                        <button type="button" onclick="signOut();">Sign out</button>
                    </div>
                </body>
            </html>
            <?php
            exit;
        } else {
            $mfaError = true;
            $mfaErrorMsg = $result['message'];
            if($isJson) {
                $auth->jsonResponse(['error' => true, 'message' => $result['message']], 400);
            }
        }
    } catch (Exception $e) {
        error_log($e);
        $mfaError = true;
        $mfaErrorMsg = "An error occurred during MFA verification.";
        if($isJson) {
            $auth->jsonResponse(['error' => true, 'message' => 'An error occurred during MFA verification.'], 500);
        }
    }
}

// Handle initial login
$error = false;
$errorMsg = "";
$mfaPending = false;
$mfaUserId = null;
$mfaUsername = null;
$mfaPassword = null;

$usr = isset($requestData["usr"]) ? $requestData["usr"] : "";
$pwd = isset($requestData["pwd"]) ? $requestData["pwd"] : "";
$csrfToken = isset($requestData["csrf_token"]) ? $requestData["csrf_token"] : null;

if($usr !== "" && $pwd !== ""){
    try{
        $result = $auth->initiateMFA($usr, $pwd, $csrfToken);
        if($result['error'] === false && isset($result['userId'])){
            // Password correct, MFA code sent
            $mfaPending = true;
            $mfaUserId = $result['userId'];
            $mfaUsername = $result['username'];
            $mfaPassword = $pwd;
            // For JSON requests, return MFA pending state
            if($isJson) {
                $auth->jsonResponse([
                    'error' => false,
                    'mfaPending' => true,
                    'userId' => $result['userId'],
                    'username' => $result['username'],
                    'message' => 'MFA code sent to your email'
                ]);
            }
        } else {
            $error = true;
            $errorMsg = $result['message'];
            if($isJson) {
                $auth->jsonResponse(['error' => true, 'message' => $result['message']], 400);
            }
        }
    } catch (Exception $e) {
        error_log($e);
        $error = true;
        $errorMsg = "An error occurred. Please try again.";
        if($isJson) {
            $auth->jsonResponse(['error' => true, 'message' => 'An error occurred. Please try again.'], 500);
        }
    }
} else {
    // Empty credentials
    if($isJson) {
        $auth->jsonResponse(['error' => true, 'message' => 'Username and password are required.'], 400);
    }
}
?>
<!DOCTYPE html>
<html>
    <head>
        <link rel="stylesheet" href="dialogs.css">
        <script src="validation.js"></script>
        <script>
            function togglePassword(){
                let pwd1 = document.getElementById("pwd");
                
                if(pwd1.type === "password"){
                    pwd1.type = "text";
                } else {
                    pwd1.type = "password";
                }
            }
            
            function showLoader(){
                var form = document.getElementById("form");
                var loader = document.getElementById("loader");
                if(form && loader){
                    form.style.display = "none";
                    loader.style.display = "flex";
                }
            }
        </script>
    </head>
    <body>
        <div class="container">
            <div id="form">
            <?php if($mfaPending): ?>
                <h1>Two-Factor Authentication</h1>
                <p>A 4-digit verification code has been sent to your email address. Please enter it below.</p>
                
                <?php if(isset($mfaError) && $mfaError): ?>
                    <span class='errorMsg'><?php echo htmlspecialchars($mfaErrorMsg); ?></span><br>
                <?php endif; ?>
                
                <form method="POST" onsubmit="showLoader()">
                    <input type="hidden" name="userId" value="<?php echo htmlspecialchars($mfaUserId); ?>">
                    <input type="hidden" name="username" value="<?php echo htmlspecialchars($mfaUsername); ?>">
                    <input type="hidden" name="password" value="<?php echo htmlspecialchars($mfaPassword); ?>">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($auth->generateCsrfToken()); ?>">
                    <label for="mfa_code">Verification Code:</label>
                    <input type="text" id="mfa_code" name="mfa_code" pattern="[0-9]{4}" maxlength="4" required><br>
                    <label for="submit"></label>
                    <input type="submit" id="submit" name="submit" value="Verify & Sign In">
                </form>
                <p><a href="SignIn.php">Start over</a></p>
            
            <?php else: ?>
                <h1>Sign In</h1>
                
                <?php if($error): ?>
                    <label></label><span class='errorMsg'><?php echo htmlspecialchars($errorMsg); ?></span><br>
                <?php endif; ?>
                
                <form method="POST" onsubmit="showLoader()">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($auth->generateCsrfToken()); ?>">
                    <label for="usr">User name:</label>
                    <input type="text" id="usr" name="usr" value="<?php echo htmlspecialchars($usr) ?>" required><br>
                    <label for="pwd">Password:</label>
                    <input type="password" id="pwd" name="pwd" required>
                    <input type="button" onclick="togglePassword()" value="&#128065;" title="Show password"><br>
                    <label for="submit"></label>
                    <input type="submit" id="submit" name="submit" value="Sign In">
                </form>
                <br>
                <label></label><span><a href="SignUp.php">Create an account</a> | <a href="passwordForgot.php">Forgot password?</a></span>
            <?php endif; ?>
            </div>
            <div id="loader" class="loaderContainer" style="display:none;">
                <div class="loader"></div>
            </div>
        </div>    
    </body>
</html>
