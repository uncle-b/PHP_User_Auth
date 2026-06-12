<?php 

$auth_muteSetup = true;
include "Auth2.php";

// General functions
function randomString($n) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $randomString = '';
    for ($i = 0; $i < $n; $i++) {
        $index = random_int(0, strlen($characters) - 1);
        $randomString .= $characters[$index];
    }
    return $randomString;
}

/*
=================================================================
*/

// First check if the secure authentication has already been set up.
if($auth->active===true){
?>
<!DOCTYPE html>
<html>
    <head>
        <link rel="stylesheet" href="dialogs/dialogs.css">
    </head>
    <body>
        <div class="container">
        <h1>Setup completed</h1>
        <p>
            Secure authentication is already set up on this server.
            If you want to execute a fresh setup, please manually remove the existing Auth database, database user and delete the "env" directory.
            Note that this will permanently delete all user accounts and information and cannot be undone.
        </p>
        </div>
    </body>
</html>
<?php
} else {

// if not, get admin user + password
if(!isset($_POST["usr"]) && !isset($_POST["pwd"])){

?>
<!DOCTYPE html>
<html>
    <head>
        <link rel="stylesheet" href="dialogs/dialogs.css">
        <script>
            function showLoader(){
                document.getELementById("loader").style.display = "flex";
                document.getELementById("form").style.display = "none";
            }
        </script>
    </head>
    <body>
        <div class="container">
        <h1>Setup secure authentication</h1>
        <p>
            By running this application, secure authentication is automatically setup on your domain. 
            After setup. please include the 'Auth2.php' module in every php page that requires authentication.
            Before you continue, please make sure that you have mySQL installed on your server and that you have sufficient rights to create database users and databases under your account.
        </p>
        
        <div id="form">
        <form method="POST" onsubmit="showLoader()">

            <h2>Sign in as administrator</h2>
            <p>
                Please provide your administrator credentials to continue. If you did not deliberately start this procedure, please do not continue. 
            </p>
            <label for="usr">Admin username:</label>
            <input type="text" id="usr" name="usr"><br>
            <label for="pwd">Admin Password:</label>
            <input type="password" id="pwd" name="pwd"><br>
            <h2>Setup system SMTP mail account</h2>
            <p>
                Please provide a system email address to use for authentication emails. (e.g. verification emails, password resets, ect.).
                Typically this would be a dedicated 'no-reply' email address. If you leave the below fields blank, you can set these manually later in the env/env.php file.
            </p>
            <label for="smtphost">SMTP Host (smtp.example.com):</label>
            <input type="text" id="smtphost" name="smtphost"><br>
            <label for="smtpport">System SMTP port number:</label>
            <input type="number" id="smtpport" name="smtpport" value=465><br>
            <label for="smtpeml">System SMTP email address:</label>
            <input type="email" id="smtpeml" name="smtpeml"><br>
            <label for="smtppwd">System SMTP email password:</label>
            <input type="password" id="smtppwd" name="smtppwd"><br>
            <label for="submit"></label>
            <input type="submit" id="submit" name="submit">

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
    // Start setting up secure authentication with the provided credentials.
    $adminUsr = $_POST["usr"];
    $adminPwd = $_POST["pwd"];
    
    $AuthId = randomString(3);

    $servername = "localhost";
    $authDBUser = "AuthUser_$AuthId";
    $authDBName = "AuthDB_$AuthId";
    $authDBPwd = randomString(16);
    $authEncrypt = randomString(32);
    $smtpHost = $_POST['smtphost'];
    $smtpPort = $_POST['smtpport'];
    $smtpEmail = $_POST['smtpeml'];
    $smtpPwd = $_POST['smtppwd'];

    try {
        $conn = new PDO("mysql:host=$servername", $adminUsr, $adminPwd);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Create the database
        $conn->exec("CREATE DATABASE $authDBName");

        // Create a new user for the database
        $conn->exec("CREATE USER '$authDBUser'@'localhost' IDENTIFIED BY '$authDBPwd'");

        // Grant privileges to the new user for the new database
        $conn->exec("GRANT ALL PRIVILEGES ON $authDBName.* TO '$authDBUser'@'localhost'");
        $conn->exec("FLUSH PRIVILEGES");

        $conn = new PDO("mysql:host=$servername;dbname=$authDBName", $authDBUser, $authDBPwd);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Create Auth table
        $q =    "CREATE TABLE accounts (
                userId INT(6) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                user TINYTEXT NOT NULL,
                email TINYTEXT NOT NULL,
                emailHash CHAR(64) NOT NULL,
                verificationCode MEDIUMINT(5) DEFAULT 0,
                passToken TINYTEXT,
                nonce TINYTEXT NOT NULL,
                loginId MEDIUMTEXT,
                resetToken TINYTEXT,
                resetExpiry INT(11) DEFAULT 0,
                verified BOOLEAN DEFAULT FALSE,
                modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )";
        $conn->exec($q);

        //Create env directory and limit permissions
        mkdir("env");
        chmod("env", 0700);

        //Write environment variables to PHP file
        $envFile = fopen("env/env.php", "w");
        $txt = "<?php\n";
        $txt.= "\$AuthSetupCompleted=true;\n";
        $txt.= "\$AuthDBName='$authDBName';\n";
        $txt.= "\$AuthDBUser='$authDBUser';\n";
        $txt.= "\$AuthDBPwd='$authDBPwd';\n";
        $txt.= "\$AuthEncryptKey='$authEncrypt';\n";
        $txt.= "\$smtpHost='$smtpHost';\n";
        $txt.= "\$smtpPort='$smtpPort';\n";
        $txt.= "\$smtpEmail='$smtpEmail';\n";
        $txt.= "\$smtpPwd='$smtpPwd';\n";
        fwrite($envFile, $txt);
        fclose($envFile);

        //Create gitignore file
        $authDir = str_replace($_SERVER["DOCUMENT_ROOT"]."/","",getcwd());
        $gitFile = fopen($_SERVER["DOCUMENT_ROOT"]."/.gitignore", "a+");
        $txt = "$authDir/env/\n";
        $txt.= "vendor/\n";
        fwrite($gitFile, $txt);
        fclose($gitFile);

        //Create composer.json
        $composer = fopen($_SERVER["DOCUMENT_ROOT"]."/composer.json", "a+");
        $txt = '{"require": {"phpmailer/phpmailer": "^7.0.0"}}';
        fwrite($composer, $txt);
        fclose($composer);

        // Install composer dependencies
        exec("composer update");

        ?>
        <!DOCTYPE html>
        <html>
            <head>
                <link rel="stylesheet" href="dialogs/dialogs.css">
            </head>
            <body>
                <div class="container">
                <h1>Setup completed</h1>
                <p>
                    Secure authentication is almost set up on this server. 
                    Please run "composer update" in the terminal of the server to install the required dependencies. After that, please test if the application is capable of sending emails through the specified SMTP server by running the <a href="emailTst.php">Auth/emailTest.php</a> script. Please see the documentation for further use instructions.
                </p>
                </div>
            </body>
        </html>
        <?php

    } catch(PDOException $e) {
        error_log("Error: " . $e->getMessage());
    ?>
        <!DOCTYPE html>
        <html>
            <head>
                <link rel="stylesheet" href="dialogs/dialogs.css">
            </head>
            <body>
                <div class="container">
                <h1>Something went wrong...</h1>
                <p>
                    The setup script did not finish correctly. Please see the server error log for details.
                </p>
                </div>
            </body>
        </html>
    <?php
    }

}
}


