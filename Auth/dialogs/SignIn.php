<?php
include "../Auth2.php";
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
        </script>
    </head>
    <body>
        < class="container">
            <h1>Sign In</h1>
            
            <?php
            $error = false;
            $errorMsg = "";
            
            $usr = isset($_POST["usr"]) ? $_POST["usr"] : "";
            $pwd = isset($_POST["pwd"]) ? $_POST["pwd"] : "";
            
            if($usr !== "" && $pwd !== ""){
                try{
                    $result = $auth->signIn($usr, $pwd);
                    if($result['error'] === false){ 
                        // Login successful

                        $cookie_name = "X-AUTH-KEY";
                        $cookie_value = $result['token'];
                        setcookie($cookie_name, $cookie_value, 0,"","",true,true);

                        $bodyToken = $result['bodyToken'];

                        ?>
                        <h1>Login successful</h1>

                        <input type='hidden' value='<?php echo $bodyToken; ?>' name='bodyToken'/>
                        <p>
                            Login succeeded. A httponly cookie with an authentication key has been set. This will be automatically sent back to the server with every request.
                            Besides that, a hidden input, named 'bodyToken' is included in this page. The value of that should be returned with every request by setting a http header named 'X-Auth-Body-Token' containing this value.
                        </p>
                        <?php
                        exit;
                    } else {
                        $error = true;
                        $errorMsg = "<span class='errorMsg'>" . htmlspecialchars($result['message']) . "</span>";
                    }
                } catch (Exception $e) {
                    error_log($e);
                    $error = true;
                    $errorMsg = "<span class='errorMsg'>An error occurred. Please try again.</span>";
                }
            }
            
            if($usr == "" || $pwd == "" || $error == true){
            ?>
            
            <form method="POST">
                <label for="usr">User name:</label>
                <input type="text" id="usr" name="usr" value="<?php echo htmlspecialchars($usr) ?>" required><br>
                <label for="pwd">Password:</label>
                <input type="password" id="pwd" name="pwd" required>
                <input type="button" onclick="togglePassword()" value="&#128065;" title="Show password"><br>
                <?php echo $errorMsg ?>
                <label for="submit"></label>
                <input type="submit" id="submit" name="submit" value="Sign In">
            </form>
            <p><a href="SignUp.php">Create an account</a> | <a href="passwordForgot.php">Forgot password?</a></p>
            
            <?php
            }
            ?>
        </div>    
    </body>
</html>
