<?php
include "../Auth2.php";

// Start session for CSRF protection
$auth->startSession();
$auth->sendSecurityHeaders();

$requestData = $auth->getRequestData();
$isJson = $auth->isJsonRequest();

$csrfToken = null; //$auth->generateCsrfToken();
$error = false;
$usrErrorMsg = "";

$usr = isset($requestData["usr"]) ? $requestData["usr"] : "";
$pwd = isset($requestData["pwd"]) ? $requestData["pwd"] : "";
$eml = isset($requestData["email"]) ? $requestData["email"] : "";
$csrfTokenPost = isset($requestData["csrf_token"]) ? $requestData["csrf_token"] : null;
?>
<!DOCTYPE html>
<html>
    <head>
        <link rel="stylesheet" href="dialogs.css">
        <script src="validation.js"></script>
        <script>
            function validateInput(){
                let subm = document.getElementById("submit");
                    subm.disabled = false;

                document.getElementById("pwd").style.backgroundColor = "#ffffff";
                document.getElementById("pwd2").style.backgroundColor = "#ffffff";
                document.getElementById("usr").style.backgroundColor = "#ffffff";
                document.getElementById("email").style.backgroundColor = "#ffffff";

                if(validatePassWord(document.getElementById("pwd"))==false){
                    subm.disabled = true;
                    document.getElementById("pwd").style.backgroundColor = "#ffcccc"
                }

                if(document.getElementById("pwd2").value !== document.getElementById("pwd").value){
                    subm.disabled = true;
                    document.getElementById("pwd2").style.backgroundColor = "#ffcccc"
                }

                if(validateEmail(document.getElementById("email"))==false){
                    subm.disabled = true;
                    document.getElementById("email").style.backgroundColor = "#ffcccc";
                }
                if(validateUserName(document.getElementById("usr"))==false){
                    subm.disabled = true;
                    console.log()
                    document.getElementById("usr").style.backgroundColor = "#ffcccc";
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
<?php
$error = false;
$usrErrorMsg = "";

$usr = isset($requestData["usr"]) ? $requestData["usr"] : "";
$pwd = isset($requestData["pwd"]) ? $requestData["pwd"] : "";
$eml = isset($requestData["email"]) ? $requestData["email"] : "";

if($usr !== ""){
    if($auth->userExists($usr)!==false){
        $error = true;
        $usrErrorMsg = "<label></label><span class='errorMsg'>User name already in use. Please choose a different name.</span><br>";
        if($isJson) {
            $auth->jsonResponse(['error' => true, 'message' => 'User name already in use. Please choose a different name.'], 400);
        }
    }
}

if($pwd !== ""){
    if($auth->validatePassword($pwd)===false){
        $error = true;
        $pswErrorMsg = "<label></label><span class='errorMsg'>Password is not strong enough.</span><br>";
        if($isJson) {
            $auth->jsonResponse(['error' => true, 'message' => 'Password is not strong enough.'], 400);
        }
    }
}

if($eml !== ""){
    if($auth->validateEmail($eml)===false){
        $error = true;
        $emlErrorMsg = "<label></label><span class='errorMsg'>Email address seems invalid.</span><br>";
        if($isJson) {
            $auth->jsonResponse(['error' => true, 'message' => 'Email address seems invalid.'], 400);
        }
    }
}

if($usr == "" || $pwd == "" || $eml == "" || $error == true){

    $csrfToken = $auth->generateCsrfToken();

    if($isJson) {
        if($usr == "" || $pwd == "" || $eml == "") {
            $auth->jsonResponse(['error' => true, 'message' => 'All fields are required.'], 400);
        } elseif (!$auth->validateCsrfToken($csrfTokenPost)) {
            $auth->jsonResponse(['error' => true, 'message' => 'Invalid CSRF token.'], 400);
        } else {
            $auth->jsonResponse(['error' => true, 'message' => 'Validation errors occurred.'], 400);
        }
    }
    
?>
    </head>
    <body>
        <div class="container">
            <h1>Sign up</h1>
            <div id="form">
            <form method="POST" onsubmit="showLoader()">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                <label for="usr">User name:</label>
                <input type="text" id="usr" name="usr" value="<?php echo htmlspecialchars($usr) ?>" onkeyup="validateInput();"><br><?php echo $usrErrorMsg ?>
                <label for="email">Email address:</label>
                <input type="email" id="email" name="email" value="<?php echo $eml ?>" onkeyup="validateInput();"><br><?php echo $emlErrorMsg ?>
                <label for="pwd">Password:</label>
                <input type="password" id="pwd" name="pwd" onkeyup="validateInput();">
                <input type="button" onclick="togglePassword()" value="&#128065;" title="Show password"><br><?php echo $pswErrorMsg ?>
                <label for="pwd2">Repeat password:</label>
                <input type="password" id="pwd2" name="pwd2" onkeyup="validateInput();"><br>
                <label for="submit"></label>
                <input type="submit" id="submit" name="submit" disabled>
            </form>
            </div>
            <div id="loader" class="loaderContainer" style="display:none;">
                <div class="loader"></div>
            </div>
        </div>    
    </body>

</html>
<?php
} else {

    //Check if username is available
    //CSRF already validated in the condition above - no need to recheck

    try{
        $res = $auth->createUser($usr, $eml, $pwd, null, $csrfTokenPost);
        if($isJson) {
            $auth->jsonResponse([
                'error' => false,
                'message' => 'Thanks for signing up. We have sent an email to verify your address. Please click the link in that email to activate your account.'
            ]);
        }
    } catch (Exception $e) {
        error_log($e);
        if($isJson) {
            $auth->jsonResponse(['error' => true, 'message' => 'An error occurred during signup.'], 500);
        }
        die;
    }
    
?>
<!DOCTYPE html>
<html>
    <head>
        <link rel="stylesheet" href="dialogs.css">
    </head>
    <body>
        <div class="container">
            <h1>Thank you</h1>
            <p>
                Thanks for signing up. We have sent an email to verify your address. Please click the link in that email to activate your account.
            </p>
        </div>    
    </body>
</html>
<?php
}
?>