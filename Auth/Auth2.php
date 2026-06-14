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
    public $userId = null;
    public $username = null;
    public $mfaCode = null;

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
            $emailHash = hash('sha256', strtolower($eml));

            error_log($encEml);

            $decryptedData = $this->decryptDataArray($encryptedData);
            error_log($decryptedData["email"]);

            $verificationCode = rand(10000,99999);

            $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
            if($con){
                $query = "INSERT INTO `accounts`(`user`, `email`, `emailHash`, `verificationCode`,`passToken`, `nonce`, `verified`) VALUES ('$usr','$encEml','$emailHash',$verificationCode,'$passToken','$nonce', 0);";
                $res = DB::query($con, $query);
                if($res!==false){
                    
                    $id = $con->insert_id;
                    $validationURL.="?account=$id&key=$verificationCode";
                    $emailText = "";
                    $subject = "Subject";
                    include "emails/emailValidation.php";
                    $this->sendEmail($eml, $subject, $message, $altMessage, $_SERVER['SERVER_NAME']);
                    return true;
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
                    $bodyToken= $this->randomString(16);
                    $payload = array(
                        "user" => $usr,
                        "userId" => $userId,
                        "loginId" => $loginId,
                        "bodyToken" => $bodyToken,
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
                            'loginId' => $loginId,
                            'bodyToken' => $bodyToken
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

    public function requestPasswordReset($username, $resetURL = null){
        $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
        if($con){
            if($resetURL === null){
                $resetURL = $_SERVER['SERVER_NAME']."/Auth/dialogs/passwordReset.php";
            }
            
            $resetToken = $this->randomString(32);
            $resetExpiry = time() + 3600; // 1 hour expiry
            
            $query = "SELECT * FROM `accounts` WHERE `user`='$username' AND `verified`=1 LIMIT 1";
            $res = DB::query($con, $query);
            
            if($res !== false && mysqli_num_rows($res) > 0){
                $row = mysqli_fetch_array($res, MYSQLI_ASSOC);
                $userId = $row['userId'];
                $decryptedData = $this->decryptDataArray([
                    "email" => $row['email'],
                    "nonce" => $row['nonce']
                ]);
                
                $email = $decryptedData['email'];
                
                $updateQuery = "UPDATE `accounts` SET `resetToken`='$resetToken', `resetExpiry`=$resetExpiry WHERE `userId`=$userId";
                $updateRes = DB::query($con, $updateQuery);
                
                if($updateRes !== false){
                    $resetLink = $resetURL . "?account=$userId&token=$resetToken";
                    $subject = "Password Reset Request";
                    
                    $message = "";
                    $altMessage = "";
                    include "emails/passwordReset.php";
                    
                    $this->sendEmail($email, $subject, $message, $altMessage, $_SERVER['SERVER_NAME']);
                    return true;
                }
            }
            
            // Always return true to prevent username enumeration
            return true;
        } else {
            error_log("No db connection..");
            throw new Exception("Invalid database connection.");
        }
    }

    public function getUserByEmail($email){
        $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
        if($con){
            $emailHash = hash('sha256', strtolower($email));
            $query = "SELECT * FROM `accounts` WHERE `emailHash`='$emailHash' AND `verified`=1 LIMIT 1";
            $res = DB::query($con, $query);
            
            if($res !== false && mysqli_num_rows($res) > 0){
                return mysqli_fetch_array($res, MYSQLI_ASSOC);
            }
            return false;
        } else {
            error_log("No db connection..");
            throw new Exception("Invalid database connection.");
        }
    }

    public function authenticateRequest(){
        // Get JWT token from X-AUTH-KEY cookie
        $jwtToken = isset($_COOKIE['X-AUTH-KEY']) ? $_COOKIE['X-AUTH-KEY'] : null;
        
        // Get bodyToken from X-Auth-Body-Token header
        $bodyToken = isset($_SERVER['HTTP_X_AUTH_BODY_TOKEN']) ? $_SERVER['HTTP_X_AUTH_BODY_TOKEN'] : null;
        
        if($jwtToken === null || $bodyToken === null){
            return false;
        }
        
        $encKey = $_ENV["AUTH_ENCRYPTION_KEY"];
        $payload = checkJWTHS256($jwtToken, $encKey);
        
        if($payload === false){
            // Invalid or tampered token
            return false;
        }
        
        // Decode payload if it's a string
        if(is_string($payload)){
            $payload = json_decode($payload, true);
            if($payload === null){
                return false;
            }
        }
        
        // Check token expiry
        if(!isset($payload['expiry']) || $payload['expiry'] < time()){
            // Token has expired
            return false;
        }
        
        // Validate bodyToken
        if(!isset($payload['bodyToken']) || $payload['bodyToken'] !== $bodyToken){
            return false;
        }
        
        // Validate loginId and userId in database
        if(!isset($payload['loginId']) || !isset($payload['userId'])){
            return false;
        }
        
        $loginId = $payload['loginId'];
        $userId = $payload['userId'];
        
        $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
        if($con === null){
            error_log("No db connection..");
            return false;
        }
        
        // Check if this userId has the specified loginId
        $query = "SELECT * FROM `accounts` WHERE `userId`=$userId AND `loginId` LIKE '%$loginId%' LIMIT 1";
        $res = DB::query($con, $query);
        
        if($res === false || mysqli_num_rows($res) === 0){
            // LoginId not found for this user
            return false;
        }
        
        // Authentication successful - set userId as public variable
        $this->userId = $userId;
        $this->username = isset($payload['user']) ? $payload['user'] : null;
        
        return true;
    }

    private function generateMFACode(){
        return str_pad(rand(0, 9999), 4, '0', STR_PAD_LEFT);
    }

    public function initiateMFA($username, $password){
        $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
        if($con === null){
            error_log("No db connection..");
            throw new Exception("Invalid database connection.");
        }
        
        $passToken = $this->makePassToken($username, $password);
        $query = "SELECT * FROM `accounts` WHERE `user`='$username' AND `verified`=1 LIMIT 1";
        $res = DB::query($con, $query);
        
        if($res !== false && mysqli_num_rows($res) > 0){
            $row = mysqli_fetch_array($res, MYSQLI_ASSOC);
            $storedPassToken = $row['passToken'];
            
            if($storedPassToken === $passToken){
                $mfaCode = $this->generateMFACode();
                $mfaExpiry = time() + 900; // 15 minutes expiry
                $userId = $row['userId'];
                $email = $this->decryptDataArray([
                    "email" => $row['email'],
                    "nonce" => $row['nonce']
                ])['email'];
                
                $updateQuery = "UPDATE `accounts` SET `mfaCode`='$mfaCode', `mfaExpiry`=$mfaExpiry WHERE `userId`=$userId";
                $updateRes = DB::query($con, $updateQuery);
                
                if($updateRes !== false){
                    $subject = "Your MFA Code";
                    $message = "Your Multi-Factor Authentication code is: <strong>$mfaCode</strong><br><br>This code will expire in 15 minutes.";
                    $altMessage = "Your Multi-Factor Authentication code is: $mfaCode. This code will expire in 15 minutes.";
                    
                    $this->sendEmail($email, $subject, $message, $altMessage, $_SERVER['SERVER_NAME']);
                    
                    return array(
                        'error' => false,
                        'message' => "MFA code sent to your email.",
                        'userId' => $userId,
                        'username' => $username
                    );
                }
            }
        }
        
        return array(
            'error' => true,
            'message' => "Invalid username or password."
        );
    }

    public function verifyMFA($userId, $code, $password = null, $username = null){
        $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
        if($con === null){
            error_log("No db connection..");
            throw new Exception("Invalid database connection.");
        }
        
        $query = "SELECT * FROM `accounts` WHERE `userId`=$userId AND `mfaExpiry` > " . time() . " LIMIT 1";
        $res = DB::query($con, $query);
        
        if($res !== false && mysqli_num_rows($res) > 0){
            $row = mysqli_fetch_array($res, MYSQLI_ASSOC);
            $storedCode = $row['mfaCode'];
            
            if($storedCode === $code){
                // MFA verified - clear the code and proceed with login
                $clearQuery = "UPDATE `accounts` SET `mfaCode`='', `mfaExpiry`=0 WHERE `userId`=$userId";
                DB::query($con, $clearQuery);
                
                // Now perform the actual sign in
                if($username !== null && $password !== null){
                    return $this->signIn($username, $password);
                }
                
                return array(
                    'error' => false,
                    'message' => "MFA verification successful."
                );
            }
        }
        
        return array(
            'error' => true,
            'message' => "Invalid or expired MFA code."
        );
    }

    public function resetPassword($userId, $resetToken, $newPassword, $newPasswordRepeat = null){
        $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
        if($con){
            if($newPasswordRepeat !== null && $newPassword !== $newPasswordRepeat){
                return array(
                    'error' => true,
                    'message' => "Passwords do not match."
                );
            }
            
            if(!$this->validatePassword($newPassword)){
                return array(
                    'error' => true,
                    'message' => "Password does not meet requirements."
                );
            }
            
            $query = "SELECT * FROM `accounts` WHERE `userId`=$userId AND `resetToken`='$resetToken' AND `resetExpiry` > " . time() . " LIMIT 1";
            $res = DB::query($con, $query);
            
            if($res !== false && mysqli_num_rows($res) > 0){
                $row = mysqli_fetch_array($res, MYSQLI_ASSOC);
                $user = $row['user'];
                
                $newPassToken = $this->makePassToken($user, $newPassword);
                
                $updateQuery = "UPDATE `accounts` SET `passToken`='$newPassToken', `loginId`='', `resetToken`='', `resetExpiry`=0 WHERE `userId`=$userId";
                $updateRes = DB::query($con, $updateQuery);
                
                if($updateRes !== false){
                    return array(
                        'error' => false,
                        'message' => "Password has been reset successfully."
                    );
                } else {
                    return array(
                        'error' => true,
                        'message' => "Failed to update password."
                    );
                }
            } else {
                return array(
                    'error' => true,
                    'message' => "Invalid or expired reset token."
                );
            }
        } else {
            error_log("No db connection..");
            throw new Exception("Invalid database connection.");
        }
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

