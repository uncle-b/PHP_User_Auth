<?php
include "../Auth2.php";
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
            
            $pwd = isset($_POST["pwd"]) ? $_POST["pwd"] : "";
            $pwd2 = isset($_POST["pwd2"]) ? $_POST["pwd2"] : "";
            
            // Validate the reset token and account
            if($account === "" || $token === ""){
                $error = true;
                $errorMsg = "Invalid password reset link.";
            }
            
            if($pwd !== "" && $pwd2 !== "" && $error === false){
                try{
                    $result = $auth->resetPassword($account, $token, $pwd, $pwd2);
                    if($result['error'] === false){ 
                        $success = true;
                        $successMsg = $result['message'];
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
            
            if($success === true){
                echo "<div class='success'><p>" . htmlspecialchars($successMsg) . "</p></div>";
                echo "<p><a href='SignIn.php'>Sign In</a></p>";
            } else {
                if($error === true && $pwd === "" && $pwd2 === ""){
                    echo "<div class='error'><p>" . htmlspecialchars($errorMsg) . "</p></div>";
                    echo "<p><a href='passwordForgot.php'>Request a new password reset link</a></p>";
                } else {
            ?>
            
            <form method="POST">
                <input type="hidden" name="account" value="<?php echo htmlspecialchars($account) ?>">
                <input type="hidden" name="token" value="<?php echo htmlspecialchars($token) ?>">
                <label for="pwd">New Password:</label>
                <input type="password" id="pwd" name="pwd" onkeyup="validatePasswordReset();" required><br>
                <label for="pwd2">Confirm New Password:</label>
                <input type="password" id="pwd2" name="pwd2" onkeyup="validatePasswordReset();" required>
                <input type="button" onclick="togglePassword()" value="&#128065;" title="Show password"><br>
                <?php if($error && $pwd !== "") echo "<span class='errorMsg'>" . htmlspecialchars($errorMsg) . "</span><br>"; ?>
                <label for="submit"></label>
                <input type="submit" id="submit" name="submit" value="Reset Password" disabled>
            </form>
            
            <?php
                }
            }
            ?>
        </div>    
    </body>
</html>
