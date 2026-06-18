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
    public $loginId = null;

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
        if($con) {
            $stmt = $con->prepare("SELECT user FROM `accounts` WHERE `user`=?");
            $stmt->bind_param('s', $user);
            if($stmt->execute()) {
                $result = $stmt->get_result();
                return $result->num_rows > 0;
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

    public function createUser($usr, $eml, $psw, $validationURL=null, $csrfToken = null){
        // Validate CSRF token for unauthenticated requests
        if ($csrfToken !== null && !$this->validateCsrfToken($csrfToken)) {
            return false;
        }

        $userExists = $this->userExists($usr);
        $emlValid = $this->validateEmail($eml);
        $pswValid = $this->validatePassword($psw);

        if($validationURL===null){
            $validationURL=$_SERVER['SERVER_NAME']."/Auth/dialogs/emailValidate.php";
        }

        if($userExists === false && $emlValid===true && $pswValid===true){

            // $passToken = $this->makePassToken($usr, $psw);
            $passToken = password_hash($psw, PASSWORD_ARGON2ID);
            $encryptedData = $this->encryptDataArray(["email"=>$eml]);
            
            $encEml = $encryptedData["email"];
            $nonce = $encryptedData["nonce"];
            $emailHash = hash('sha256', strtolower($eml));

            $decryptedData = $this->decryptDataArray($encryptedData);
            $verificationCode = random_int(10000, 99999);

            $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
            if($con){
                $stmt = $con->prepare("INSERT INTO `accounts`(`user`, `email`, `emailHash`, `verificationCode`, `passToken`, `nonce`, `verified`) VALUES (?, ?, ?, ?, ?, ?, 0)");
                $stmt->bind_param('sssiss', $usr, $encEml, $emailHash, $verificationCode, $passToken, $nonce);
                if($stmt->execute()){
                    
                    $id = $stmt->insert_id;
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
            $stmt = $con->prepare("SELECT * FROM `accounts` WHERE userId=? AND verificationCode=?");
            $stmt->bind_param('ii', $id, $key);
            if($stmt->execute()){
                $result = $stmt->get_result();
                if($result->num_rows > 0){
                    $stmt2 = $con->prepare("UPDATE `accounts` SET verified=1 WHERE userId=?");
                    $stmt2->bind_param('i', $id);
                    return $stmt2->execute();
                }
            }
            return false;
        } else {
            error_log("No db connection..");
            throw new Exception("Invalid database connection.");
        }
    }

    public function startSession(){
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }

    /**
     * Check if the current request has JSON content type
     */
    public function isJsonRequest() {
        $contentType = isset($_SERVER['CONTENT_TYPE']) ? $_SERVER['CONTENT_TYPE'] : '';
        return strpos($contentType, 'application/json') !== false;
    }

    /**
     * Get request data from either JSON body or POST, based on Content-Type
     */
    public function getRequestData() {
        if ($this->isJsonRequest()) {
            $json = file_get_contents('php://input');
            $data = json_decode($json, true);
            return $data !== null ? $data : [];
        }
        return $_POST;
    }

    /**
     * Send a JSON response and exit
     */
    public function jsonResponse($data, $statusCode = 200) {
        http_response_code($statusCode);
        header('Content-Type: application/json');
        echo json_encode($data);
        exit;
    }

    public function generateCsrfToken(){
        $this->startSession();
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }

    public function validateCsrfToken($token){
        $this->startSession();
        if (empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
            return false;
        }
        // Optionally: regenerate token after use (one-time use)
        // $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        return true;
    }

    public function signIn($usr, $psw, $csrfToken = null){
        // Validate CSRF token for unauthenticated requests
        if ($csrfToken !== null && !$this->validateCsrfToken($csrfToken)) {
            return array(
                'error' => true,
                'message' => "Invalid CSRF token."
            );
        }
        
        $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
        if($con){
            //$this->makePassToken($usr, $psw);
            $stmt = $con->prepare("SELECT * FROM `accounts` WHERE `user`=? AND `verified`=1 LIMIT 1");
            $stmt->bind_param('s', $usr);
            
            if($stmt->execute()){
                $res = $stmt->get_result();
                if($res !== false && $res->num_rows > 0){
                    $row = $res->fetch_array(MYSQLI_ASSOC);
                    $storedPassToken = $row['passToken'];
                    $userId = $row['userId'];
                        
                    if(password_verify($psw, $storedPassToken)){ //;$storedPassToken === $passToken
                        // Password correct!
                        $loginId = $this->randomString(32) . '.' . time();
                        $bodyToken= $this->randomString(16);
                        $payload = array(
                            "user" => $usr,
                            "userId" => $userId,
                            "loginId" => $loginId,
                            "bodyToken" => $bodyToken,
                            "issued" => time(),
                            "expiry" => (time() + 3600)  // = today + 1 hour
                        );

                        $encKey = $_ENV["AUTH_ENCRYPTION_KEY"];
                        $token = generateJWTHS256($payload, $encKey);
                        
                        $loginIds = $row['loginId'];
                        if($loginIds == "" || $loginIds === null){
                            $newLoginIds = $loginId;
                        } else {
                            $newLoginIds = $loginIds . "," . $loginId;
                        }
                        
                        $stmt2 = $con->prepare("UPDATE `accounts` SET `loginId`=? WHERE `user`=?");
                        $stmt2->bind_param('ss', $newLoginIds, $usr);
                        $updateRes = $stmt2->execute();
                        
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
                            'message' => "Login failed: Invalid username or password."
                        );
                    }
                } else {
                    return array(
                        'error' => true,
                        'message' => "Login failed: Invalid username or password."
                    );
                }
            }
        } else {
            error_log("No db connection..");
            throw new Exception("Invalid database connection.");
        }
    }

    public function signOut($onAllAccounts=false){

        if($this->loginId==null || $this->userId==null){
            $authenticated = $this->authenticateRequest();
        }

        if($this->userId!==null && $this->loginId!==null){
            
            $id = $this->userId;
            $loginId = $this->loginId;

            $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
            if($con){
                $searchPattern = "%" . $loginId . "%";
                $stmt = $con->prepare("SELECT * FROM `accounts` WHERE userId=? AND loginId LIKE ? LIMIT 1");
                $stmt->bind_param('is', $id, $searchPattern);
                
                if($stmt->execute()){
                    $res = $stmt->get_result();
                    if($res !== false && $res->num_rows > 0){
                        $row = $res->fetch_array(MYSQLI_ASSOC);
                        $loginIds = $row['loginId'];

                        if($loginIds!==""){
                            if($onAllAccounts == false){
                                $ids=explode(",",$loginIds);
                                // Extract base loginId for comparison (without timestamp)
                                $baseLoginId = explode('.', $loginId)[0];
                                for($i=0;$i<count($ids);$i++){
                                    $storedBaseId = explode('.', $ids[$i])[0];
                                    if($storedBaseId === $baseLoginId){
                                        array_splice($ids, $i, 1);
                                        break;
                                    }
                                }
                                $newLoginIds=join(",", $ids);
                            } else {
                                $newLoginIds="";
                            }
                        } else {
                            $newLoginIds = "";
                        }

                        $stmt2 = $con->prepare("UPDATE `accounts` SET loginId=? WHERE userId=?");
                        $stmt2->bind_param('si', $newLoginIds, $id);
                        return $stmt2->execute();
                    }
                }
                return false;
            } else {
                error_log("No db connection..");
                throw new Exception("Invalid database connection.");
            }




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

    public function requestPasswordReset($username, $resetURL = null, $csrfToken = null){
        // Validate CSRF token for unauthenticated requests
        if ($csrfToken !== null && !$this->validateCsrfToken($csrfToken)) {
            return false;
        }
        
        $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
        if($con){
            if($resetURL === null){
                $resetURL = $_SERVER['SERVER_NAME']."/Auth/dialogs/passwordReset.php";
            }
            
            $resetToken = $this->randomString(32);
            $resetExpiry = time() + 3600; // 1 hour expiry
            
            $stmt = $con->prepare("SELECT * FROM `accounts` WHERE `user`=? AND `verified`=1 LIMIT 1");
            $stmt->bind_param('s', $username);
            
            if($stmt->execute()){
                $res = $stmt->get_result();
                if($res !== false && $res->num_rows > 0){
                    $row = $res->fetch_array(MYSQLI_ASSOC);
                    $userId = $row['userId'];
                    $decryptedData = $this->decryptDataArray([
                        "email" => $row['email'],
                        "nonce" => $row['nonce']
                    ]);
                    
                    $email = $decryptedData['email'];
                    
                    $stmt2 = $con->prepare("UPDATE `accounts` SET `resetToken`=?, `resetExpiry`=? WHERE `userId`=?");
                    $stmt2->bind_param('sii', $resetToken, $resetExpiry, $userId);
                    $updateRes = $stmt2->execute();
                    
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
            $stmt = $con->prepare("SELECT * FROM `accounts` WHERE `emailHash`=? AND `verified`=1 LIMIT 1");
            $stmt->bind_param('s', $emailHash);
            
            if($stmt->execute()){
                $res = $stmt->get_result();
                if($res !== false && $res->num_rows > 0){
                    return $res->fetch_array(MYSQLI_ASSOC);
                }
            }
            return false;
        } else {
            error_log("No db connection..");
            throw new Exception("Invalid database connection.");
        }
    }


    public function isSecure() {
        $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || $_SERVER['SERVER_PORT'] == 443;
        if($secure === false){
            error_log("WARNING: You are not using HTTPS! Please enable HTTPS for secure client communication!");
        }
    }

    public function authenticateRequest(){

        // Get JWT token from cookie (PHP converts hyphens to underscores)
        $jwtToken = isset($_COOKIE['X_AUTH_KEY']) ? $_COOKIE['X_AUTH_KEY'] : (isset($_COOKIE['X-AUTH-KEY']) ? $_COOKIE['X-AUTH-KEY'] : null);
        
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
        $username = isset($payload['user']) ? $payload['user'] : null;
        $currentTime = time();

        $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
        if($con === null){
            error_log("No db connection..");
            return false;
        }
        
        // Extract base loginId (without timestamp) for search
        $baseLoginId = explode('.', $loginId)[0];
        $searchPattern = "%" . $baseLoginId . "%";
        
        $stmt = $con->prepare("SELECT * FROM `accounts` WHERE `userId`=? AND `loginId` LIKE ? LIMIT 1");
        $stmt->bind_param('is', $userId, $searchPattern);
        
        if($stmt->execute()){
            $res = $stmt->get_result();
            if($res === false || $res->num_rows === 0){
                // LoginId not found for this user
                return false;
            }
            
            $row = $res->fetch_array(MYSQLI_ASSOC);
            $allLoginIds = $row['loginId'];
            
            // Cleanup expired loginIds
            $loginIdsArray = explode(',', $allLoginIds);
            $validLoginIds = [];
            $foundCurrent = false;
            
            foreach($loginIdsArray as $storedId) {
                $parts = explode('.', $storedId);
                $storedBaseId = $parts[0];
                $storedTimestamp = count($parts) > 1 ? (int)$parts[1] : $currentTime;
                
                // Keep if not expired (1 hour = 3600s)
                if($currentTime - $storedTimestamp < 3600) {
                    $validLoginIds[] = $storedId;
                }
                
                // Check if this is our current loginId
                if($storedBaseId === $baseLoginId) {
                    $foundCurrent = true;
                }
            }
            
            // Update database with cleaned loginIds
            $newLoginIds = implode(',', $validLoginIds);
            $stmt2 = $con->prepare("UPDATE `accounts` SET loginId=? WHERE userId=?");
            $stmt2->bind_param('si', $newLoginIds, $userId);
            $stmt2->execute();
            
            if(!$foundCurrent){
                return false;
            }
            
            // Auto-renew JWT if expiring soon (< 5 minutes left)
            $tokenNeedsRenewal = ($payload['expiry'] - $currentTime < 300);
            
            if($tokenNeedsRenewal) {
                $newLoginId = $this->randomString(32) . '.' . $currentTime;
                $newPayload = [
                    "user" => $username,
                    "userId" => $userId,
                    "loginId" => $newLoginId,
                    "bodyToken" => $bodyToken,
                    "issued" => $currentTime,
                    "expiry" => $currentTime + 3600
                ];
                
                $newToken = generateJWTHS256($newPayload, $encKey);
                
                // Update cookie with new JWT
                $https = $this->isSecure();
                $cookieOptions = [
                    'expires' => $currentTime + 3600,
                    'path' => '/',
                    'domain' => '.' . $_SERVER['SERVER_NAME'],
                    'secure' => $https,
                    'httponly' => true,
                    'samesite' => 'Strict'
                ];
                setcookie("X_AUTH_KEY", $newToken, $cookieOptions);
                
                // Add new loginId to database
                $updatedLoginIds = $newLoginIds . ',' . $newLoginId;
                $stmt3 = $con->prepare("UPDATE `accounts` SET loginId=? WHERE userId=?");
                $stmt3->bind_param('si', $updatedLoginIds, $userId);
                $stmt3->execute();
                
                $loginId = $newLoginId;
                $payload = $newPayload;
            }
        } else {
            return false;
        }
        
        // Authentication successful
        $this->userId = $userId;
        $this->username = $username;
        $this->loginId = $loginId;
        return true;
    }

    private function generateMFACode(){
        return str_pad(random_int(0, 9999), 4, '0', STR_PAD_LEFT);
    }

    public function initiateMFA($username, $password, $csrfToken = null){
        // Validate CSRF token for unauthenticated requests
        if ($csrfToken !== null && !$this->validateCsrfToken($csrfToken)) {
            return array(
                'error' => true,
                'message' => "Invalid CSRF token."
            );
        }
        
        $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
        if($con === null){
            error_log("No db connection..");
            throw new Exception("Invalid database connection.");
        }
        
        //$this->makePassToken($username, $password);
        $stmt = $con->prepare("SELECT * FROM `accounts` WHERE `user`=? AND `verified`=1 LIMIT 1");
        $stmt->bind_param('s', $username);
        
        if($stmt->execute()){
            $res = $stmt->get_result();
            if($res !== false && $res->num_rows > 0){
                $row = $res->fetch_array(MYSQLI_ASSOC);
                $storedPassToken = $row['passToken'];
                
                if(password_verify($password, $storedPassToken)){ // $storedPassToken === $passToken
                    $mfaCode = $this->generateMFACode();
                    $mfaExpiry = time() + 900; // 15 minutes expiry
                    $userId = $row['userId'];
                    $email = $this->decryptDataArray([
                        "email" => $row['email'],
                        "nonce" => $row['nonce']
                    ])['email'];
                    
                    $stmt2 = $con->prepare("UPDATE `accounts` SET `mfaCode`=?, `mfaExpiry`=? WHERE `userId`=?");
                    $stmt2->bind_param('sii', $mfaCode, $mfaExpiry, $userId);
                    $updateRes = $stmt2->execute();
                    
                    if($updateRes !== false){

                        include "emails/MFAMessage.php";

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
        }
        
        return array(
            'error' => true,
            'message' => "Invalid username or password."
        );
    }

    public function verifyMFA($userId, $code, $password = null, $username = null, $csrfToken = null){
        // Validate CSRF token for unauthenticated requests
        if ($csrfToken !== null && !$this->validateCsrfToken($csrfToken)) {
            return array(
                'error' => true,
                'message' => "Invalid CSRF token."
            );
        }
        
        $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
        if($con === null){
            error_log("No db connection..");
            throw new Exception("Invalid database connection.");
        }
        
        $currentTime = time();
        $stmt = $con->prepare("SELECT * FROM `accounts` WHERE `userId`=? AND `mfaExpiry` > ? LIMIT 1");
        $stmt->bind_param('ii', $userId, $currentTime);
        
        if($stmt->execute()){
            $res = $stmt->get_result();
            if($res !== false && $res->num_rows > 0){
                $row = $res->fetch_array(MYSQLI_ASSOC);
                $storedCode = $row['mfaCode'];
                
                if($storedCode === $code){
                    // MFA verified - clear the code and proceed with login
                    $stmt2 = $con->prepare("UPDATE `accounts` SET `mfaCode`='', `mfaExpiry`=0 WHERE `userId`=?");
                    $stmt2->bind_param('i', $userId);
                    $stmt2->execute();
                    
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
        }
        
        return array(
            'error' => true,
            'message' => "Invalid or expired MFA code."
        );
    }

    public function resetPassword($userId, $resetToken, $newPassword, $newPasswordRepeat = null, $csrfToken = null){
        // Validate CSRF token for unauthenticated requests
        if ($csrfToken !== null && !$this->validateCsrfToken($csrfToken)) {
            return array(
                'error' => true,
                'message' => "Invalid CSRF token."
            );
        }
        
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
            
            $currentTime = time();
            $stmt = $con->prepare("SELECT * FROM `accounts` WHERE `userId`=? AND `resetToken`=? AND `resetExpiry` > ? LIMIT 1");
            $stmt->bind_param('isi', $userId, $resetToken, $currentTime);
            
            if($stmt->execute()){
                $res = $stmt->get_result();
                if($res !== false && $res->num_rows > 0){
                    $row = $res->fetch_array(MYSQLI_ASSOC);
                    $user = $row['user'];
                
                    $newPassToken = password_hash($newPassword, PASSWORD_ARGON2ID); //$this->makePassToken($user, $newPassword);
                    
                    $stmt2 = $con->prepare("UPDATE `accounts` SET `passToken`=?, `loginId`='', `resetToken`='', `resetExpiry`=0 WHERE `userId`=?");
                    $stmt2->bind_param('si', $newPassToken, $userId);
                    $updateRes = $stmt2->execute();
                    
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

