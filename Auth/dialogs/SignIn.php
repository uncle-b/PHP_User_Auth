<?php
include "../Auth2.php";

// Handle MFA verification
if(isset($_POST["mfa_code"]) && isset($_POST["userId"]) && isset($_POST["username"]) && isset($_POST["password"])){
    $userId = $_POST["userId"];
    $username = $_POST["username"];
    $password = $_POST["password"];
    $mfaCode = $_POST["mfa_code"];
    
    try{
        $result = $auth->verifyMFA($userId, $mfaCode, $password, $username);
        if($result['error'] === false && isset($result['token'])){
            // MFA verified and login complete
            $cookie_name = "X-AUTH-KEY";
            $cookie_value = $result['token'];

            $https=false;
            if($auth->isSecure()){
                $https=true;
            };

            setcookie($cookie_name, $cookie_value, 0, "/", "", $https, true);

            $bodyToken = $result['bodyToken'];
            
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
        }
    } catch (Exception $e) {
        error_log($e);
        $mfaError = true;
        $mfaErrorMsg = "An error occurred during MFA verification.";
    }
}

// Handle initial login
$error = false;
$errorMsg = "";
$mfaPending = false;
$mfaUserId = null;
$mfaUsername = null;
$mfaPassword = null;

$usr = isset($_POST["usr"]) ? $_POST["usr"] : "";
$pwd = isset($_POST["pwd"]) ? $_POST["pwd"] : "";

if($usr !== "" && $pwd !== ""){
    try{
        $result = $auth->initiateMFA($usr, $pwd);
        if($result['error'] === false && isset($result['userId'])){
            // Password correct, MFA code sent
            $mfaPending = true;
            $mfaUserId = $result['userId'];
            $mfaUsername = $result['username'];
            $mfaPassword = $pwd;
        } else {
            $error = true;
            $errorMsg = $result['message'];
        }
    } catch (Exception $e) {
        error_log($e);
        $error = true;
        $errorMsg = "An error occurred. Please try again.";
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
