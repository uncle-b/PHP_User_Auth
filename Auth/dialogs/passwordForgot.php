<?php
include "../Auth2.php";
?>
<!DOCTYPE html>
<html>
    <head>
        <link rel="stylesheet" href="dialogs.css">
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
            <h1>Forgot Password</h1>
            <p>Enter your username and we will send a password reset link to your email address.</p>
            
            <?php
            $error = false;
            $success = false;
            $errorMsg = "";
            $successMsg = "";
            
            $username = isset($_POST["username"]) ? $_POST["username"] : "";
            
            if($username !== ""){
                if(strlen($username) >= 3){  // Basic validation
                    try{
                        $result = $auth->requestPasswordReset($username);
                        if($result === true){ 
                            $success = true;
                            $successMsg = "If an account exists with this username, a password reset link has been sent to the associated email address.";
                        } else {
                            $error = true;
                            $errorMsg = "Failed to process password reset request.";
                        }
                    } catch (Exception $e) {
                        error_log($e);
                        $error = true;
                        $errorMsg = "An error occurred. Please try again.";
                    }
                } else {
                    $error = true;
                    $errorMsg = "Please enter a valid username.";
                }
            }
            
            if($success === true){
                ?>
                <!DOCTYPE html>
                <html>
                    <head><link rel="stylesheet" href="dialogs.css"></head>
                    <body>
                        <div class="container">
                            <p>
                                <?php echo htmlspecialchars($successMsg); ?>
                            </p>
                            <p><a href='SignIn.php'>Back to Sign In</a></p>
                        </div>
                    </body>
                </html>
                <?php
            } else {
            ?>
            
            <div id="form">
            <form method="POST" onsubmit="showLoader()">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" value="<?php echo htmlspecialchars($username) ?>" required><br>
                <?php if($error) echo "<span class='errorMsg'>" . htmlspecialchars($errorMsg) . "</span><br>"; ?>
                <label for="submit"></label>
                <input type="submit" id="submit" name="submit" value="Send Reset Link">
            </form>
            <p><a href="SignIn.php">Back to Sign In</a></p>
            </div>
            <div id="loader" class="loaderContainer" style="display:none;">
                <div class="loader"></div>
            </div>
            
            <?php
            }
            ?>
        </div>    
    </body>
</html>
