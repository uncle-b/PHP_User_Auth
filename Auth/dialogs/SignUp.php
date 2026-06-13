<?php
include "../Auth2.php";
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

$usr = isset($_POST["usr"]) ? $_POST["usr"] : "";
$pwd = isset($_POST["pwd"]) ? $_POST["pwd"] : "";
$eml = isset($_POST["email"]) ? $_POST["email"] : "";

if($usr !== ""){
    if($auth->userExists($usr)!==false){
        $error = true;
        $usrErrorMsg = "<label></label><span class='errorMsg'>User name already in use. Please choose a different name.</span><br>";
    }
}

if($pwd !== ""){
    if($auth->validatePassword($pwd)===false){
        $error = true;
        $pswErrorMsg = "<label></label><span class='errorMsg'>Password is not strong enough.</span><br>";
    }
}

if($eml !== ""){
    if($auth->validateEmail($eml)===false){
        $error = true;
        $emlErrorMsg = "<label></label><span class='errorMsg'>Email address seems invalid.</span><br>";
    }
}

if($usr == "" || $pwd == "" || $eml == "" || $error == true){

?>
    </head>
    <body>
        <div class="container">
            <div id="form">
            <form method="POST" onsubmit="showLoader()">
                <label for="usr">User name:</label>
                <input type="text" id="usr" name="usr" value="<?php echo $usr ?>" onkeyup="validateInput();"><br><?php echo $usrErrorMsg ?>
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
    try{
        $res = $auth->createUser($usr, $eml, $pwd);
    } catch (Exception $e) {
        error_log($e);
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