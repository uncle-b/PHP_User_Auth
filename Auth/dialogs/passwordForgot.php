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
            
            $username = isset($requestData["username"]) ? $requestData["username"] : "";
            $csrfTokenPost = isset($requestData["csrf_token"]) ? $requestData["csrf_token"] : null;
            
            if($username !== ""){
                if(strlen($username) >= 3){  // Basic validation
                    // Validate CSRF token
                    if(!$auth->validateCsrfToken($csrfTokenPost)) {
                        $error = true;
                        $errorMsg = "Invalid request.";
                        if($isJson) {
                            $auth->jsonResponse(['error' => true, 'message' => 'Invalid request.'], 400);
                        }
                    } else {
                        try{
                            $result = $auth->requestPasswordReset($username, null, $csrfTokenPost);
                            if($result === true){ 
                                $success = true;
                                $successMsg = "If an account exists with this username, a password reset link has been sent to the associated email address.";
                                if($isJson) {
                                    $auth->jsonResponse(['error' => false, 'message' => $successMsg]);
                                }
                            } else {
                                $error = true;
                                $errorMsg = "Failed to process password reset request.";
                                if($isJson) {
                                    $auth->jsonResponse(['error' => true, 'message' => 'Failed to process password reset request.'], 400);
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
                    $error = true;
                    $errorMsg = "Please enter a valid username.";
                    if($isJson) {
                        $auth->jsonResponse(['error' => true, 'message' => 'Please enter a valid username.'], 400);
                    }
                }
            } else {
                if($isJson) {
                    $auth->jsonResponse(['error' => true, 'message' => 'Username is required.'], 400);
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
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
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
