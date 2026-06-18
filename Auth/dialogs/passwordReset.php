<?php
include "../Auth2.php";

// Start session for CSRF protection
$auth->startSession();
$csrfToken = $auth->generateCsrfToken();

$requestData = $auth->getRequestData();
$isJson = $auth->isJsonRequest();

?>
<!DOCTYPE html>
<html>
    <head>
        <link rel="stylesheet" href="dialogs.css">
        <script src="validation.js"></script>
        <script>
            function validatePasswordReset(){
                let pwd1 = document.getElementById("pwd");
                let pwd2 = document.getElementById("pwd2");
                let subm = document.getElementById("submit");
                
                pwd1.style.backgroundColor = "#ffffff";
                pwd2.style.backgroundColor = "#ffffff";
                
                if(validatePassWord(pwd1)==false){
                    subm.disabled = true;
                    pwd1.style.backgroundColor = "#ffcccc";
                }
                
                if(pwd2.value !== pwd1.value){
                    subm.disabled = true;
                    pwd2.style.backgroundColor = "#ffcccc";
                }
                
                if(validatePassWord(pwd1)===true && pwd2.value === pwd1.value){
                    subm.disabled = false;
                }
            }
            
            function togglePassword(){
                let pwd1 = document.getElementById("pwd");
                let pwd2 = document.getElementById("pwd2");
                
                if(pwd1.type === "password"){
                    pwd1.type = "text"; pwd2.type = "text";
                } else {
                    pwd1.type = "password"; pwd2.type = "password";
                }
            }
        </script>
        <script>
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
            <h1>Reset Password</h1>
            
            <?php
            $error = false;
            $success = false;
            $errorMsg = "";
            $successMsg = "";
            
            $account = isset($_GET["account"]) ? $_GET["account"] : "";
            $token = isset($_GET["token"]) ? $_GET["token"] : "";
            
            $pwd = isset($requestData["pwd"]) ? $requestData["pwd"] : "";
            $pwd2 = isset($requestData["pwd2"]) ? $requestData["pwd2"] : "";
            $csrfTokenPost = isset($requestData["csrf_token"]) ? $requestData["csrf_token"] : null;
            
            // Validate the reset token and account
            if($account === "" || $token === ""){
                $error = true;
                $errorMsg = "Invalid password reset link.";
                if($isJson) {
                    $auth->jsonResponse(['error' => true, 'message' => 'Invalid password reset link.'], 400);
                }
            }
            
            if($pwd !== "" && $pwd2 !== "" && $error === false){
                // Validate CSRF token
                if(!$auth->validateCsrfToken($csrfTokenPost)) {
                    $error = true;
                    $errorMsg = "Invalid request.";
                    if($isJson) {
                        $auth->jsonResponse(['error' => true, 'message' => 'Invalid request.'], 400);
                    }
                } else {
                    try{
                        $result = $auth->resetPassword($account, $token, $pwd, $pwd2, $csrfTokenPost);
                        if($result['error'] === false){ 
                            $success = true;
                            $successMsg = $result['message'];
                            if($isJson) {
                                $auth->jsonResponse(['error' => false, 'message' => $result['message']]);
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
                }
            } else {
                if($isJson && ($pwd === "" || $pwd2 === "")) {
                    $auth->jsonResponse(['error' => true, 'message' => 'Passwords are required.'], 400);
                }
            }
            
            if($success === true){
                echo "<div class='success'><p>" . htmlspecialchars($successMsg) . "</p></div>";
                echo "<p><a href='SignIn.php'>Sign In</a></p>";
            } else {
                if($error === true && $pwd === "" && $pwd2 === ""){
                    echo "<div class='error'><p>" . htmlspecialchars($errorMsg) . "</p></div>";
                    echo "<p><a href='passwordForgot.php'>Request a new password reset link</a></p>";
                } else {
            ?>
            
            <div id="form">
            <form method="POST" onsubmit="showLoader()">
                <input type="hidden" name="account" value="<?php echo htmlspecialchars($account) ?>">
                <input type="hidden" name="token" value="<?php echo htmlspecialchars($token) ?>">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                <label for="pwd">New Password:</label>
                <input type="password" id="pwd" name="pwd" onkeyup="validatePasswordReset();" required><br>
                <label for="pwd2">Confirm New Password:</label>
                <input type="password" id="pwd2" name="pwd2" onkeyup="validatePasswordReset();" required>
                <input type="button" onclick="togglePassword()" value="&#128065;" title="Show password"><br>
                <?php if($error && $pwd !== "") echo "<span class='errorMsg'>" . htmlspecialchars($errorMsg) . "</span><br>"; ?>
                <label for="submit"></label>
                <input type="submit" id="submit" name="submit" value="Reset Password" disabled>
            </form>
            </div>
            <div id="loader" class="loaderContainer" style="display:none;">
                <div class="loader"></div>
            </div>
            
            <?php
                }
            }
            ?>
        </div>    
    </body>
</html>
