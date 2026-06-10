<?php
include "../Auth2.php";

$account = $_GET["account"];
$key = $_GET["key"];

$result = $auth->verifyAccount($account, $key);

if($result){

?>
<!DOCTYPE html>
<html>
    <head>
        <link rel="stylesheet" href="dialogs.css">
    </head>
    <body>
        <div class="container">
            <h1>Email verified</h1>
            <p>
                Your email address has been verified. You can now log in.
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
        <link rel="stylesheet" href="dialogs.css">
    </head>
    <body>
        <div class="container">
            <h1>Verification failed</h1>
            <p>
                Sorry, we could not verify your email address.
            </p>
        </div>    
    </body>

</html>
<?php
}
