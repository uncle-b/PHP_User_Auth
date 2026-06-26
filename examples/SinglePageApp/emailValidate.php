<?php
include "../../Auth/Auth2.php";

$account = $_GET["account"] ?? null;
$key = $_GET["key"] ?? null;

if ($account && $key) {
    // Clear verification code immediately after use (one-time use)
    $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
    if($con) {
        $stmt = $con->prepare("UPDATE `accounts` SET `verificationCode`=0 WHERE `userId`=? AND `verificationCode`=?");
        $stmt->bind_param('ii', $account, $key);
        $stmt->execute();
    }
}

$result = $auth->verifyAccount($account, $key);

if($result){

?>
<!DOCTYPE html>
<html>
    <head>
        <link rel="stylesheet" href="SinglePage.css">
    </head>
    <body>
        <div class="page">
            <h1>Email verified</h1>
            <p>
                Your email address has been verified. You can now <a href="index.php">sign in</a>.
            </p>
        </div>    
    </body>

</html>
<?php
} else {
?>
<!DOCTYPE html>
<html>
    <head>
        <link rel="stylesheet" href="SinglePage.css">
    </head>
    <body>
        <div class="container">
            <h1>Verification failed</h1>
            <p>
                Sorry, we could not verify your email address.
                <a href="index.php">Please try again.</a>
            </p>
        </div>    
    </body>

</html>
<?php
}
