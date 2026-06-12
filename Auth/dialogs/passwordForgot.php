<?php
include "../Auth2.php";
?>
<!DOCTYPE html>
<html>
    <head>
        <link rel="stylesheet" href="dialogs.css">
    </head>
    <body>
        <div class="container">
            <h1>Forgot Password</h1>
            <p>Enter your email address and we will send you a password reset link.</p>
            
            <?php
            $error = false;
            $success = false;
            $errorMsg = "";
            $successMsg = "";
            
            $email = isset($_POST["email"]) ? $_POST["email"] : "";
            
            if($email !== ""){
                if($auth->validateEmail($email)){
                    try{
                        $result = $auth->requestPasswordReset($email);
                        if($result === true){ 
                            $success = true;
                            $successMsg = "If an account exists with this email address, a password reset link has been sent.";
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
                    $errorMsg = "Please enter a valid email address.";
                }
            }
            
            if($success === true){
                echo "<div class='success'><p>" . htmlspecialchars($successMsg) . "</p></div>";
                echo "<p><a href='SignIn.php'>Back to Sign In</a></p>";
            } else {
            ?>
            
            <form method="POST">
                <label for="email">Email address:</label>
                <input type="email" id="email" name="email" value="<?php echo htmlspecialchars($email) ?>" required><br>
                <?php if($error) echo "<span class='errorMsg'>" . htmlspecialchars($errorMsg) . "</span><br>"; ?>
                <label for="submit"></label>
                <input type="submit" id="submit" name="submit" value="Send Reset Link">
            </form>
            <p><a href="SignIn.php">Back to Sign In</a></p>
            
            <?php
            }
            ?>
        </div>    
    </body>
</html>
