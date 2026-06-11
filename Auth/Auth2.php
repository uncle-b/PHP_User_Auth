<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

// Load composer dependencies
if(file_exists($_SERVER["DOCUMENT_ROOT"]."/vendor/autoload.php")){
  require $_SERVER["DOCUMENT_ROOT"].'/vendor/autoload.php';  
} else {
  // Fallback for when composer is not installed.
  if(file_exists($_SERVER["DOCUMENT_ROOT"]."/vendor/phpmailer/phpmailer/src/PHPMailer.php")){
    require $_SERVER["DOCUMENT_ROOT"]."/vendor/phpmailer/phpmailer/src/PHPMailer.php";
    require $_SERVER["DOCUMENT_ROOT"]."/vendor/phpmailer/phpmailer/src/SMTP.php"; 
    require $_SERVER["DOCUMENT_ROOT"]."/vendor/phpmailer/phpmailer/src/Exception.php"; 
  } else {
    error_log("PHPMailer not found. Get it from https://github.com/phpmailer/phpmailer.");
  }
}

include "DB.php";
include "JWT.php";

class Auth{
    
    public $active = false;
    public $authDir = "";

    function __construct(){

        //Set Auth dir path.
        $docRoot  = $_SERVER["DOCUMENT_ROOT"];
        $included_files = get_included_files();
        $pth = explode("/", $included_files[1]);
        array_pop($pth);
        $this->authDir = str_replace($docRoot, "", join("/",$pth));
        $this->authDir = substr($this->authDir, 1, strlen($this->authDir)-1);

        //Check if environment variables are available
        if(isset($_ENV["AUTH_SETUP_COMPLETED"]) && $_ENV["AUTH_SETUP_COMPLETED"]==true){
            $this->active = true;

        // if not, try to load them.
        } else {
            if(file_exists("$docRoot/$this->authDir/env/env.php")){
                include "$docRoot/$this->authDir/env/env.php"; // Contains only $AuthSetupCompleted, $AuthDBName, $AuthDBUser and $AuthDBPwd variables.
                $this->setEnvVariable("AUTH_DB_NAME", $AuthDBName);
                $this->setEnvVariable("AUTH_DB_USER", $AuthDBUser);
                $this->setEnvVariable("AUTH_DB_PWD", $AuthDBPwd);
                $this->setEnvVariable("AUTH_ENCRYPTION_KEY", $AuthEncryptKey);
                $this->setEnvVariable("AUTH_SETUP_COMPLETED", $AuthSetupCompleted);
                $this->setEnvVariable("AUTH_SMTP_HOST", $smtpHost);
                $this->setEnvVariable("AUTH_SMTP_PORT", $smtpPort);
                $this->setEnvVariable("AUTH_SMTP_EMAIL", $smtpEmail);   
                $this->setEnvVariable("AUTH_SMTP_PWD", $smtpPwd);

                if($_ENV["AUTH_SETUP_COMPLETED"]==true){
                    $this->active = true;
                }
            } else {
                error_log("$docRoot/$this->authDir/env/env.php does not exist");
            }
        }
    }

    private function setEnvVariable($key, $value){
        if (!array_key_exists($key, $_SERVER) && !array_key_exists($key, $_ENV)) {
                putenv(sprintf('%s=%s', $key, $value));
                $_ENV[$key] = $value;
                $_SERVER[$key] = $value;
        }
    }

    public function randomString($n) {
        $characters = '!#()*-<>_^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $randomString = '';
        for ($i = 0; $i < $n; $i++) {
            $index = random_int(0, strlen($characters) - 1);
            $randomString .= $characters[$index];
        }
        return $randomString;
    }

    public function userExists($user){
        $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
        if($con){
            $query = "SELECT user FROM `accounts` WHERE `user`='$user'";
            error_log($query);
            $res = DB::singleResultQuery($con, $query, "user");
            error_log("res=$res");
            if($res!==false){
                return true;
            }
            return false;
        } else {
            error_log("No db connection..");
            throw new Exception("Invalid database connection.");
        }
    }

    public function validatePassword($pwd){
        if(preg_match("/^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*-]).{8,}$/", $pwd)){
            return true;
        }
        return false;
    }

    public function validateEmail($eml){
        if (filter_var($eml, FILTER_VALIDATE_EMAIL)){
            return true;
        }
        return false;
    }

    private function makePassToken($user, $password){
       return base64_encode(hash_hmac('sha256', "$user", $password, true));
    }

    public function encryptDataArray($dataArray){

        $encKey = $_ENV["AUTH_ENCRYPTION_KEY"];
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        foreach ($dataArray as $key => $value) {
            $cipherText = sodium_crypto_secretbox($value, $nonce, $encKey);
            $dataArray[$key] = bin2hex($cipherText);
        }

        $dataArray["nonce"]=bin2hex($nonce);
        return $dataArray;
    }

    public function decryptDataArray($dataArray){

        $encKey = $_ENV["AUTH_ENCRYPTION_KEY"];
        $nonce = hex2bin($dataArray["nonce"]);

        foreach ($dataArray as $key => $value) {
            $decryptedText = sodium_crypto_secretbox_open(hex2bin($value), $nonce, $encKey);
            $dataArray[$key] = $decryptedText;
        }

        $dataArray["nonce"]=$nonce;
        return $dataArray;
        
    }

    public function createUser($usr, $eml, $psw, $validationURL=null){

        $userExists = $this->userExists($usr);
        $emlValid = $this->validateEmail($eml);
        $pswValid = $this->validatePassword($psw);

        if($validationURL===null){
            $validationURL=$_SERVER['SERVER_NAME']."/Auth/dialogs/emailValidate.php";
        }

        if($userExists === false && $emlValid===true && $pswValid===true){


            $passToken = $this->makePassToken($usr, $psw);
            $encryptedData = $this->encryptDataArray(["email"=>$eml]);
            
            $encEml = $encryptedData["email"];
            $nonce = $encryptedData["nonce"];

            error_log($encEml);

            $decryptedData = $this->decryptDataArray($encryptedData);
            error_log($decryptedData["email"]);

            $verificationCode = rand(10000,99999);

            $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
            if($con){
                $query = "INSERT INTO `accounts`(`user`, `email`, `verificationCode`,`passToken`, `nonce`, `verified`) VALUES ('$usr','$encEml',$verificationCode,'$passToken','$nonce', 0);";
                $res = DB::query($con, $query);
                if($res!==false){
                    
                    $id = $con->insert_id;
                    $validationURL.="?account=$id&key=$verificationCode";
                    $emailText = "";
                    $subject = "Subject";
                    include "emails/emailValidation.php";
                    $this->sendEmail($eml, $subject, $message, $altMessage, $_SERVER['SERVER_NAME']);

                }
                return false;
            } else {
                error_log("No db connection..");
                throw new Exception("Invalid database connection.");
            }
        }
    }

    public function verifyAccount($id,$key){
        $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
        if($con){
            $query = "SELECT * FROM `accounts` WHERE userId=$id AND verificationCode=$key;";
            $res = DB::query($con, $query);
            if($res!==false){
                $query="UPDATE `accounts` SET verified=1 WHERE userId=$id";
                return DB::query($con, $query);
            }
            return false;
        } else {
            error_log("No db connection..");
            throw new Exception("Invalid database connection.");
        }
    }

    public function signIn($usr, $psw){
        $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
        if($con){
            $passToken = $this->makePassToken($usr, $psw);
            $query = "SELECT * FROM `accounts` WHERE `user`='$usr' AND `verified`=1 LIMIT 1";
            $res = DB::query($con, $query);
            
            if($res !== false && mysqli_num_rows($res) > 0){
                $row = mysqli_fetch_array($res, MYSQLI_ASSOC);
                $storedPassToken = $row['passToken'];
                $userId = $row['userId'];

                if($storedPassToken === $passToken){
                    // Password correct!
                    $loginId = $this->randomString(32);
                    $payload = array(
                        "user" => $usr,
                        "userId" => $userId,
                        "loginId" => $loginId,
                        "issued" => time(),
                        "expiry" => (time() + 31536000)  // = today + 1 year
                    );

                    $encKey = $_ENV["AUTH_ENCRYPTION_KEY"];
                    $token = generateJWTHS256($payload, $encKey);
                    
                    $loginIds = $row['loginId'];
                    if($loginIds == "" || $loginIds === null){
                        $query = "UPDATE `accounts` SET `loginId`='$loginId' WHERE `user`='$usr';";
                    } else {
                        $loginIds .= "," . $loginId;
                        $query = "UPDATE `accounts` SET `loginId`='$loginIds' WHERE `user`='$usr';";
                    }
                    
                    $updateRes = DB::query($con, $query);
                    
                    if($updateRes !== false){
                        return array(
                            'error' => false,
                            'message' => "Login successful.",
                            'token' => $token,
                            'loginId' => $loginId
                        );
                    } else {
                        return array(
                            'error' => true,
                            'message' => "Failed to update login session."
                        );
                    }
                } else {
                    return array(
                        'error' => true,
                        'message' => "Login failed: Invalid credentials."
                    );
                }
            } else {
                return array(
                    'error' => true,
                    'message' => "Login failed: User not found or account not verified."
                );
            }
        } else {
            error_log("No db connection..");
            throw new Exception("Invalid database connection.");
        }
    }

    public function testEmail($mailto, $displayName = "Authenticator"){

        //Create an instance; passing `true` enables exceptions
        $mail = new PHPMailer(true);

        try {
            //Server settings
            $mail->SMTPDebug = SMTP::DEBUG_SERVER;                      //Enable verbose debug output
            $mail->isSMTP();                                            //Send using SMTP
            $mail->Host       = $_ENV["AUTH_SMTP_HOST"];                //Set the SMTP server to send through
            $mail->SMTPAuth   = true;                                   //Enable SMTP authentication
            $mail->Username   = $_ENV["AUTH_SMTP_EMAIL"];               //SMTP username
            $mail->Password   = $_ENV["AUTH_SMTP_PWD"];                 //SMTP password
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;            //Enable implicit TLS encryption
            $mail->Port       = $_ENV["AUTH_SMTP_PORT"];                //TCP port to connect to; use 587 if you have set `SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS`

            //Recipients
            $mail->setFrom($_ENV["AUTH_SMTP_EMAIL"], $displayName);
            $mail->addAddress($mailto);                                 //Add a recipient

            //Content
            $mail->isHTML(true);                                  //Set email format to HTML
            $mail->Subject = 'Auth library test email';
            $mail->Body    = 'This email is sent to verify that the system email address is propoerly set up.';
            $mail->AltBody = 'This email is sent to verify that the system email address is propoerly set up.';
            $mail->send();
        } catch (Exception $e) {error_log($mail->ErrorInfo);}
    }

    public function sendEmail($mailto, $subject, $message, $altMessage = "", $displayName = "Authenticator"){

        //Create an instance; passing `true` enables exceptions
        $mail = new PHPMailer(true);

        try {
            //Server settings
            // $mail->SMTPDebug = SMTP::DEBUG_SERVER;                   //Enable verbose debug output
            $mail->isSMTP();                                            //Send using SMTP
            $mail->Host       = $_ENV["AUTH_SMTP_HOST"];                //Set the SMTP server to send through
            $mail->SMTPAuth   = true;                                   //Enable SMTP authentication
            $mail->Username   = $_ENV["AUTH_SMTP_EMAIL"];               //SMTP username
            $mail->Password   = $_ENV["AUTH_SMTP_PWD"];                 //SMTP password
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;            //Enable implicit TLS encryption
            $mail->Port       = $_ENV["AUTH_SMTP_PORT"];                //TCP port to connect to; use 587 if you have set `SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS`

            //Recipients
            $mail->setFrom($_ENV["AUTH_SMTP_EMAIL"], $displayName);
            $mail->addAddress($mailto);                                 //Add a recipient

            //Content
            $mail->isHTML(true);                                  //Set email format to HTML
            $mail->Subject = $subject;
            $mail->Body    = $message;
            $mail->AltBody = $altMessage;
            $mail->send();
        } catch (Exception $e) {error_log($mail->ErrorInfo);}
    }
}

/*
====================================================================
*/

$auth = new Auth();

if($auth->active === false && $auth_muteSetup !== true){
    $docRoot  = $_SERVER["DOCUMENT_ROOT"];
    $included_files = get_included_files();
    $pth = explode("/", $included_files[1]);
    array_pop($pth);
    $dir = str_replace($docRoot, "", join("/",$pth));
    header("Location:".$dir."/setupScript.php");
    exit;
}

