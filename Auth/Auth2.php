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
        // Enforce HTTPS for all authentication requests
        $this->enforceHTTPS();

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
            $envFile = "$docRoot/$this->authDir/env/env.php";
            if(file_exists($envFile)){
                // Validate env file permissions - should not be world-readable
                $fileInfo = @stat($envFile);
                if($fileInfo && ($fileInfo['mode'] & 0002)) {
                    error_log("CRITICAL: Environment file has world-writable permissions: $envFile");
                    throw new Exception("Insecure environment file permissions");
                }
                
                include $envFile; // Contains only $AuthSetupCompleted, $AuthDBName, $AuthDBUser and $AuthDBPwd variables.
                
                // Validate required variables exist and are non-empty
                $requiredVars = ['AuthDBName', 'AuthDBUser', 'AuthDBPwd', 'AuthEncryptKey', 'AuthSetupCompleted'];
                foreach ($requiredVars as $var) {
                    if (!isset($$var) || empty($$var)) {
                        error_log("Missing or empty required configuration: $var");
                        throw new Exception("Incomplete authentication configuration");
                    }
                }
                
                $this->setEnvVariable("AUTH_DB_NAME", $AuthDBName);
                $this->setEnvVariable("AUTH_DB_USER", $AuthDBUser);
                $this->setEnvVariable("AUTH_DB_PWD", $AuthDBPwd);
                $this->setEnvVariable("AUTH_ENCRYPTION_KEY", $AuthEncryptKey);
                $this->setEnvVariable("AUTH_SETUP_COMPLETED", $AuthSetupCompleted);
                
                // Only set SMTP vars if they exist
                if(isset($smtpHost)) $this->setEnvVariable("AUTH_SMTP_HOST", $smtpHost);
                if(isset($smtpPort)) $this->setEnvVariable("AUTH_SMTP_PORT", $smtpPort);
                if(isset($smtpEmail)) $this->setEnvVariable("AUTH_SMTP_EMAIL", $smtpEmail);   
                if(isset($smtpPwd)) $this->setEnvVariable("AUTH_SMTP_PWD", $smtpPwd);

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

    /**
     * Log security events to database
     * 
     * @param string $eventType Type of event (login_success, login_failure, password_reset, etc.)
     * @param int|null $userId User ID if known
     * @param string|null $username Username if known
     * @param string|null $details Additional details
     */
    private function logSecurityEvent($eventType, $userId = null, $username = null, $details = null) {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        
        $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
        if($con === null) {
            error_log("Security event logging failed: No database connection");
            return false;
        }
        
        try {
            $stmt = $con->prepare("INSERT INTO security_log (userId, username, event_type, ip_address, user_agent, details) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->bind_param('isssss', $userId, $username, $eventType, $ip, $ua, $details);
            return $stmt->execute();
        } catch (Exception $e) {
            error_log("Security event logging error: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Check if account is locked
     * 
     * @param array $row Account row from database
     * @return bool True if account is locked
     */
    private function isAccountLocked($row) {
        if (isset($row['locked_until']) && $row['locked_until'] !== null) {
            $lockedUntil = strtotime($row['locked_until']);
            return $lockedUntil > time();
        }
        return false;
    }

    /**
     * Get hashed IP and User Agent for binding to JWT
     * 
     * @return array Array with 'ip' and 'ua' hashes
     */
    private function getClientFingerprint() {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        return [
            'ip' => hash('sha256', $ip),
            'ua' => hash('sha256', $ua)
        ];
    }

    /**
     * Validate loginId format to prevent IDOR attacks
     * 
     * @param string $loginId The loginId to validate
     * @return bool True if valid
     */
    private function validateLoginId($loginId) {
        // loginId format: randomString(32) . '.' . timestamp
        // randomString uses: !#()*-<>_^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
        return preg_match('/^[a-zA-Z0-9!#()\*\-<>_^]+\.\d+$/', $loginId);
    }

    /**
     * Check if rate limit is exceeded for an endpoint
     * 
     * @param string $endpoint The endpoint name (e.g., 'login', 'mfa', 'password_reset')
     * @param string|null $identifier Optional identifier (IP, username, etc.)
     * @param int $maxAttempts Maximum allowed attempts
     * @param int $lockoutPeriod Lockout period in seconds
     * @return bool True if rate limit is exceeded
     */
    private function checkRateLimit($endpoint, $identifier = null, $maxAttempts = 5, $lockoutPeriod = 3600) {
        if ($identifier === null) {
            $identifier = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        }
        
        $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
        if($con === null) return false;
        
        $currentTime = date('Y-m-d H:i:s');
        
        // Check if currently locked
        $stmt = $con->prepare("SELECT locked_until FROM rate_limits WHERE identifier=? AND endpoint=? LIMIT 1");
        $stmt->bind_param('ss', $identifier, $endpoint);
        $stmt->execute();
        $res = $stmt->get_result();
        
        if($res !== false && $res->num_rows > 0) {
            $row = $res->fetch_array(MYSQLI_ASSOC);
            if ($row['locked_until'] !== null && strtotime($row['locked_until']) > time()) {
                return true; // Still locked
            }
        }
        
        // Check attempt count
        $stmt2 = $con->prepare("SELECT attempt_count, last_attempt FROM rate_limits WHERE identifier=? AND endpoint=? LIMIT 1");
        $stmt2->bind_param('ss', $identifier, $endpoint);
        $stmt2->execute();
        $res2 = $stmt2->get_result();
        
        $attemptCount = 0;
        $lastAttempt = null;
        
        if($res2 !== false && $res2->num_rows > 0) {
            $row2 = $res2->fetch_array(MYSQLI_ASSOC);
            $attemptCount = $row2['attempt_count'];
            $lastAttempt = $row2['last_attempt'];
            
            // Reset count if last attempt was more than 1 hour ago
            if ($lastAttempt !== null && strtotime($lastAttempt) < time() - 3600) {
                $attemptCount = 0;
            }
        }
        
        $attemptCount++;
        $lockedUntil = null;
        
        if ($attemptCount >= $maxAttempts) {
            $lockedUntil = date('Y-m-d H:i:s', time() + $lockoutPeriod);
            $this->logSecurityEvent('rate_limit_exceeded', null, null, "Rate limit exceeded for endpoint $endpoint from $identifier");
        }
        
        // Update or insert rate limit record
        if($res2 !== false && $res2->num_rows > 0) {
            $stmt3 = $con->prepare("UPDATE rate_limits SET attempt_count=?, last_attempt=?, locked_until=? WHERE identifier=? AND endpoint=?");
            $stmt3->bind_param('issss', $attemptCount, $currentTime, $lockedUntil, $identifier, $endpoint);
            $stmt3->execute();
        } else {
            $stmt4 = $con->prepare("INSERT INTO rate_limits (identifier, endpoint, attempt_count, last_attempt, locked_until) VALUES (?, ?, ?, ?, ?)");
            $stmt4->bind_param('ssiss', $identifier, $endpoint, $attemptCount, $currentTime, $lockedUntil);
            $stmt4->execute();
        }
        
        return ($lockedUntil !== null);
    }

    public function randomString($n) {
        $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
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
            throw new Exception("Authentication service unavailable. Please try again later.");
        }
    }

    public function validatePassword($pwd){
        if(preg_match("/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*-]).{8,}$/", $pwd)){
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
                throw new Exception("Authentication service unavailable. Please try again later.");
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
            throw new Exception("Authentication service unavailable. Please try again later.");
        }
    }

    public function startSession(){
        if (session_status() === PHP_SESSION_NONE) {
            // Prevent session fixation by regenerating session ID
            session_start();
            if (!isset($_SESSION['initiated'])) {
                session_regenerate_id(true);
                $_SESSION['initiated'] = true;
            }
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
     * Sanitize input string to prevent XSS
     */
    public function sanitizeInput($input) {
        if (is_array($input)) {
            return array_map([$this, 'sanitizeInput'], $input);
        }
        if (is_string($input)) {
            // Remove null bytes and control characters
            $input = preg_replace('/[\x00-\x1F\x7F]/u', '', $input);
            // Trim whitespace
            $input = trim($input);
            return $input;
        }
        return $input;
    }

    /**
     * Get request data from either JSON body or POST, based on Content-Type
     */
    public function getRequestData() {
        if ($this->isJsonRequest()) {
            $json = file_get_contents('php://input');
            $data = json_decode($json, true);
            return $data !== null ? $this->sanitizeInput($data) : [];
        }
        return $this->sanitizeInput($_POST);
    }

    /**
     * Send security headers
     */
    public function sendSecurityHeaders() {
        // Prevent clickjacking
        header("X-Frame-Options: DENY");
        // Prevent MIME sniffing
        header("X-Content-Type-Options: nosniff");
        // Enable XSS protection
        header("X-XSS-Protection: 1; mode=block");
        // Referrer policy
        header("Referrer-Policy: strict-origin-when-cross-origin");
        // Permissions policy
        header("Permissions-Policy: geolocation=(), microphone=(), camera=()");
        // Content Security Policy - current host only
        header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'");
    }

    /**
     * Send a JSON response and exit
     */
    public function jsonResponse($data, $statusCode = 200) {
        $jsonContent = json_encode($data);
        $this->sendSecurityHeaders();
        http_response_code($statusCode);
        header('Content-Type: application/json');
        header('Content-Length: ' . strlen($jsonContent));
        echo $jsonContent;
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
            $this->logSecurityEvent('csrf_invalid', null, null, 'Invalid CSRF token validation attempt');
            return false;
        }
        // Rotate token after use (one-time use)
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        return true;
    }

    public function signIn($usr, $psw, $csrfToken = null){
        // Rate limiting check
        if ($this->checkRateLimit('login', $usr, 5, 3600)) {
            $this->logSecurityEvent('rate_limit_blocked', null, $usr, 'Login attempt blocked due to rate limiting');
            return array(
                'error' => true,
                'message' => "Too many login attempts. Please try again later."
            );
        }
        
        // Validate CSRF token for unauthenticated requests
        if ($csrfToken !== null && !$this->validateCsrfToken($csrfToken)) {
            $this->logSecurityEvent('csrf_failure', null, $usr, 'Invalid CSRF token during signIn');
            return array(
                'error' => true,
                'message' => "Invalid CSRF token."
            );
        }
        
        // Fix session fixation: regenerate session ID
        $this->startSession();
        session_regenerate_id(true);
        
        $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
        if($con){
            $stmt = $con->prepare("SELECT * FROM `accounts` WHERE `user`=? AND `verified`=1 LIMIT 1");
            $stmt->bind_param('s', $usr);
            
            if($stmt->execute()){
                $res = $stmt->get_result();
                if($res !== false && $res->num_rows > 0){
                    $row = $res->fetch_array(MYSQLI_ASSOC);
                    $storedPassToken = $row['passToken'];
                    $userId = $row['userId'];
                    
                    // Check if account is locked
                    if ($this->isAccountLocked($row)) {
                        $lockedUntil = $row['locked_until'];
                        $this->logSecurityEvent('account_locked', $userId, $usr, "Account locked until $lockedUntil");
                        return array(
                            'error' => true,
                            'message' => "Account locked due to too many failed attempts. Please try again later."
                        );
                    }
                        
                    if(password_verify($psw, $storedPassToken)){ 
                        // Check password strength and re-hash if needed with stronger parameters
                        if (password_needs_rehash($storedPassToken, PASSWORD_ARGON2ID, ['memory_cost' => 65536, 'time_cost' => 4, 'threads' => 2])) {
                            $newPassToken = password_hash($psw, PASSWORD_ARGON2ID, ['memory_cost' => 65536, 'time_cost' => 4, 'threads' => 2]);
                            $updateStmt = $con->prepare("UPDATE `accounts` SET `passToken`=?, `failed_attempts`=0 WHERE `userId`=?");
                            $updateStmt->bind_param('si', $newPassToken, $userId);
                            $updateStmt->execute();
                            $storedPassToken = $newPassToken;
                        }
                        
                        // <--------------------!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                        // Reset failed attempts on successful login
                        $resetStmt = $con->prepare("UPDATE `accounts` SET `failed_attempts`=0, `locked_until`=NULL WHERE `userId`=?");
                        $resetStmt->bind_param('i', $userId);
                        $resetStmt->execute();
                        
                        $resetStmt = $con->prepare("UPDATE `rate_limits` SET `attempt_count`=0 WHERE `identifier`=?");
                        $resetStmt->bind_param('s', $usr);
                        $resetStmt->execute();


                        // Password correct!
                        $loginId = $this->randomString(32) . '.' . time();
                        $bodyToken= $this->randomString(16);
                        $fingerprint = $this->getClientFingerprint();
                        
                        $payload = array(
                            "user" => $usr,
                            "userId" => $userId,
                            "loginId" => $loginId,
                            "bodyToken" => $bodyToken,
                            "ip" => $fingerprint['ip'],
                            "ua" => $fingerprint['ua'],
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
                            $this->logSecurityEvent('login_success', $userId, $usr, 'User logged in successfully');
                            return array(
                                'error' => false,
                                'message' => "Login successful.",
                                'token' => $token,
                                'loginId' => $loginId,
                                'bodyToken' => $bodyToken,
                                'userId'=> $userId
                            );
                        } else {
                            $this->logSecurityEvent('login_failure', $userId, $usr, 'Failed to update login session');
                            return array(
                                'error' => true,
                                'message' => "Failed to update login session."
                            );
                        }
                    } else {
                        // Increment failed attempts
                        $failedAttempts = $row['failed_attempts'] ?? 0;
                        $failedAttempts++;
                        $lockUntil = null;
                        if ($failedAttempts >= 5) {
                            $lockUntil = date('Y-m-d H:i:s', time() + 3600); // Lock for 1 hour
                        }
                        $updateStmt = $con->prepare("UPDATE `accounts` SET `failed_attempts`=?, `locked_until`=? WHERE `userId`=?");
                        $updateStmt->bind_param('isi', $failedAttempts, $lockUntil, $userId);
                        $updateStmt->execute();
                        
                        $this->logSecurityEvent('login_failure', $userId, $usr, "Invalid password. Failed attempts: $failedAttempts");
                        return array(
                            'error' => true,
                            'message' => "Authentication failed."
                        );
                    }
                } else {
                    $this->logSecurityEvent('login_failure', null, $usr, 'User not found or not verified');
                    // Generic message to prevent username enumeration
                    return array(
                        'error' => true,
                        'message' => "Authentication failed."
                    );
                }
            }
        } else {
            error_log("No db connection..");
            throw new Exception("Authentication service unavailable. Please try again later.");
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
                throw new Exception("Authentication service unavailable. Please try again later.");
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
        // Rate limiting check
        if ($this->checkRateLimit('password_reset', $username, 3, 3600)) {
            $this->logSecurityEvent('rate_limit_blocked', null, $username, 'Password reset blocked due to rate limiting');
            return false;
        }
        
        // Validate CSRF token for unauthenticated requests
        if ($csrfToken !== null && !$this->validateCsrfToken($csrfToken)) {
            $this->logSecurityEvent('csrf_failure', null, $username, 'Invalid CSRF token in password reset request');
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
            
            $userFound = false;
            if($stmt->execute()){
                $res = $stmt->get_result();
                if($res !== false && $res->num_rows > 0){
                    $userFound = true;
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
                        $this->logSecurityEvent('password_reset_requested', $userId, $username, "Password reset email sent to $email");
                    }
                }
            }
            
            // Generic response to prevent username enumeration
            // Log the attempt but don't reveal if user exists
            if (!$userFound) {
                $this->logSecurityEvent('password_reset_attempt', null, $username, 'Password reset attempted for non-existent or unverified user');
            }
            return true;
        } else {
            error_log("No db connection..");
            throw new Exception("Authentication service unavailable. Please try again later.");
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
            throw new Exception("Authentication service unavailable. Please try again later.");
        }
    }


    public function isSecure() {
        $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || $_SERVER['SERVER_PORT'] == 443;
        return $secure;
    }

    public function enforceHTTPS() {
        $secure = $this->isSecure();
        if($secure === false){
            error_log("WARNING: You are not using HTTPS! Please enable HTTPS for secure client communication!");
            // Only enforce HTTPS if not in setup mode (allows setup over HTTP for initial configuration)
            if (!isset($GLOBALS['auth_muteSetup']) || $GLOBALS['auth_muteSetup'] !== true) {
                // Redirect to HTTPS or block access
                if (!empty($_SERVER['HTTP_HOST']) && !empty($_SERVER['REQUEST_URI'])) {
                    $redirectUrl = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
                    header('Location: ' . $redirectUrl);
                    exit;
                } else {
                    // If we can't redirect, block access
                    header('HTTP/1.1 403 Forbidden');
                    echo 'HTTPS is required for this application.';
                    exit;
                }
            }
        }
        return $secure;
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
            $this->logSecurityEvent('jwt_invalid', null, null, 'Invalid or tampered JWT token');
            return false;
        }

        // Decode payload if it's a string
        if(is_string($payload)){
            $payload = json_decode($payload, true);
            if($payload === null){
                $this->logSecurityEvent('jwt_decode_failed', null, null, 'Failed to decode JWT payload');
                return false;
            }
        }

        // Check token expiry
        if(!isset($payload['expiry']) || $payload['expiry'] < time()){
            // Token has expired
            $this->logSecurityEvent('jwt_expired', null, null, 'JWT token expired');
            return false;
        }
        
        // Validate bodyToken
        if(!isset($payload['bodyToken']) || $payload['bodyToken'] !== $bodyToken){
            $this->logSecurityEvent('bodytoken_mismatch', null, null, 'Body token does not match');
            return false;
        }

        // Validate loginId and userId in database
        if(!isset($payload['loginId']) || !isset($payload['userId'])){
            $this->logSecurityEvent('jwt_missing_fields', null, null, 'Missing loginId or userId in JWT');
            return false;
        }
        
        $loginId = $payload['loginId'];
        $userId = $payload['userId'];
        $username = isset($payload['user']) ? $payload['user'] : null;
        $currentTime = time();
        
        // Fix IDOR: Validate loginId format
        if (!$this->validateLoginId($loginId)) {
            $this->logSecurityEvent('invalid_loginid_format', $userId, $username, "Invalid loginId format: $loginId");
            return false;
        }
        
        // Fix JWT binding: Verify IP and User Agent match
        $currentFingerprint = $this->getClientFingerprint();
        if (isset($payload['ip']) && $payload['ip'] !== $currentFingerprint['ip']) {
            $this->logSecurityEvent('jwt_ip_mismatch', $userId, $username, "IP address changed. Token IP: {$payload['ip']}, Current IP: {$currentFingerprint['ip']}");
            return false;
        }

        if (isset($payload['ua']) && $payload['ua'] !== $currentFingerprint['ua']) {
            $this->logSecurityEvent('jwt_ua_mismatch', $userId, $username, "User agent changed");
            return false;
        }

        $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
        if($con === null){
            error_log("No db connection..");
            return false;
        }

        // Extract base loginId (without timestamp) for search
        $baseLoginId = explode('.', $loginId)[0];
        $likeStatement = "%" . $baseLoginId . "%";
        // Fix IDOR: Use exact match instead of LIKE to prevent pattern injection
        $stmt = $con->prepare("SELECT * FROM `accounts` WHERE `userId`=? AND `loginId` LIKE ? LIMIT 1");
        $stmt->bind_param('is', $userId, $likeStatement);
        
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
                    'domain' => '', // Current host only
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
        return str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    }

    /**
     * Generate a unique fingerprint for the current device/browser
     * Uses user agent, IP address, and server salt for security
     * 
     * @return string SHA-256 hash of device identifiers
     */
    private function generateDeviceFingerprint(){
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $salt = $_ENV['AUTH_ENCRYPTION_KEY'] ?? 'default_salt';
        return hash('sha256', $ua . $ip . $salt);
    }

    /**
     * Check if the current device is trusted for the given user
     * 
     * @param int $userId The user ID to check
     * @return bool True if device is trusted and not expired
     */
    public function isTrustedDevice($userId){
        $fp = $this->generateDeviceFingerprint();
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

        $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
        if($con === null) return false;

        $currentTime = date('Y-m-d H:i:s');
        $stmt = $con->prepare("SELECT id FROM trusted_devices 
                              WHERE userId = ? AND device_hash = ? 
                              AND expires_at > ? 
                              AND ip_address = ? AND user_agent = ?
                              LIMIT 1");
        $stmt->bind_param('issss', $userId, $fp, $currentTime, $ip, $ua);
        $stmt->execute();
        $res = $stmt->get_result();
        
        if($res !== false && $res->num_rows > 0){
            // Update last_used timestamp
            $updateStmt = $con->prepare("UPDATE trusted_devices SET last_used = NOW() WHERE id = ?");
            $row = $res->fetch_array(MYSQLI_ASSOC);
            $updateStmt->bind_param('i', $row['id']);
            $updateStmt->execute();
            return true;
        }
        return false;
    }

    /**
     * Add the current device to the user's trusted devices list
     * 
     * @param int $userId The user ID to add the device for
     * @param int $durationDays Number of days until the trust expires (default: 30)
     * @return bool True if device was added successfully
     */
    public function addTrustedDevice($userId, $durationDays = 30){
        $fp = $this->generateDeviceFingerprint();
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $expires = date('Y-m-d H:i:s', strtotime("+$durationDays days"));

        $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
        if($con === null) return false;

        // Check if device already exists for this user
        $stmt = $con->prepare("SELECT id FROM trusted_devices WHERE userId = ? AND device_hash = ? LIMIT 1");
        $stmt->bind_param('is', $userId, $fp);
        $stmt->execute();
        $res = $stmt->get_result();
        
        if($res !== false && $res->num_rows > 0){
            // Device already exists, update expiry
            $row = $res->fetch_array(MYSQLI_ASSOC);
            $updateStmt = $con->prepare("UPDATE trusted_devices SET expires_at = ?, last_used = NOW() WHERE id = ?");
            $updateStmt->bind_param('si', $expires, $row['id']);
            return $updateStmt->execute();
        } else {
            // Add new trusted device
            $stmt2 = $con->prepare("INSERT INTO trusted_devices 
                                  (userId, device_hash, user_agent, ip_address, expires_at)
                                  VALUES (?, ?, ?, ?, ?)");
            $stmt2->bind_param('issss', $userId, $fp, $ua, $ip, $expires);
            return $stmt2->execute();
        }
    }

    /**
     * Remove a trusted device by ID
     * 
     * @param int $deviceId The device ID to remove
     * @param int $userId The user ID (for ownership verification)
     * @return bool True if device was removed successfully
     */
    public function removeTrustedDevice($deviceId, $userId){
        $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
        if($con === null) return false;

        $stmt = $con->prepare("DELETE FROM trusted_devices WHERE id = ? AND userId = ?");
        $stmt->bind_param('ii', $deviceId, $userId);
        return $stmt->execute();
    }

    /**
     * Get all trusted devices for a user
     * 
     * @param int $userId The user ID
     * @return array Array of trusted devices
     */
    public function getTrustedDevices($userId){
        $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
        if($con === null) return [];

        $stmt = $con->prepare("SELECT id, device_hash, user_agent, ip_address, created_at, expires_at, last_used 
                              FROM trusted_devices WHERE userId = ? ORDER BY last_used DESC");
        $stmt->bind_param('i', $userId);
        $stmt->execute();
        $res = $stmt->get_result();
        
        if($res !== false && $res->num_rows > 0){
            $devices = [];
            while($row = $res->fetch_array(MYSQLI_ASSOC)){
                $devices[] = $row;
            }
            return $devices;
        }
        return [];
    }

    public function initiateMFA($username, $password, $csrfToken = null, $skipMfaIfTrusted = false){
        // Rate limiting check
        if ($this->checkRateLimit('mfa_initiate', $username, 5, 3600)) {
            $this->logSecurityEvent('rate_limit_blocked', null, $username, 'MFA initiation blocked due to rate limiting');
            return array(
                'error' => true,
                'message' => "Too many attempts. Please try again later."
            );
        }
        
        $con = DB::connect($_ENV["AUTH_DB_USER"], $_ENV["AUTH_DB_PWD"], $_ENV["AUTH_DB_NAME"]);
        if($con === null){
            error_log("No db connection..");
            throw new Exception("Authentication service unavailable. Please try again later.");
        }

        //$this->makePassToken($username, $password);
        $stmt = $con->prepare("SELECT * FROM `accounts` WHERE `user`=? AND `verified`=1 LIMIT 1");
        $stmt->bind_param('s', $username);
        
        $userFound = false;
        $accountLocked = false;
        $userId = null;

        if($stmt->execute()){

            $res = $stmt->get_result();

            if($res !== false && $res->num_rows > 0){
                $userFound = true;
                $row = $res->fetch_array(MYSQLI_ASSOC);
                $storedPassToken = $row['passToken'];
                $userId = $row['userId'];

                // Check if account is locked
                if ($this->isAccountLocked($row)) {
                    $accountLocked = true;
                    $lockedUntil = $row['locked_until'];
                    $this->logSecurityEvent('account_locked', $userId, $username, "Account locked until $lockedUntil");
                } else if(password_verify($password, $storedPassToken)){ 

                    // Reset failed attempts on successful password verification
                    $resetStmt = $con->prepare("UPDATE `accounts` SET `failed_attempts`=0, `locked_until`=NULL WHERE `userId`=?");
                    $resetStmt->bind_param('i', $userId);
                    $resetStmt->execute();
                    
                    $resetStmt = $con->prepare("UPDATE `rate_limits` SET `attempt_count`=0 WHERE `identifier`=?");
                    $resetStmt->bind_param('s', $username);
                    $resetStmt->execute();

                    $email = $this->decryptDataArray([
                        "email" => $row['email'],
                        "nonce" => $row['nonce']
                    ])['email'];

                    // Check if device is trusted and MFA should be skipped
                    if ($skipMfaIfTrusted && $this->isTrustedDevice($userId)) {
                        // Device is trusted - perform sign in directly
                        $this->logSecurityEvent('mfa_skipped_trusted_device', $userId, $username, 'MFA skipped for trusted device');
                        return $this->signIn($username, $password, $csrfToken);
                    }

                    // Only validate CSRF if we're actually going to send MFA code
                    if ($csrfToken !== null && !$this->validateCsrfToken($csrfToken)) {
                        $this->logSecurityEvent('csrf_failure', null, $username, 'Invalid CSRF token in initiateMFA');
                        return array(
                            'error' => true,
                            'message' => "Invalid CSRF token."
                        );
                    }

                    // Standard MFA flow
                    $mfaCode = $this->generateMFACode();
                    $mfaExpiry = time() + 900; // 15 minutes expiry
                    
                    $stmt2 = $con->prepare("UPDATE `accounts` SET `mfaCode`=?, `mfaExpiry`=?, `failed_attempts`=0, `locked_until`=NULL WHERE `userId`=?");
                    $stmt2->bind_param('sii', $mfaCode, $mfaExpiry, $userId);
                    $updateRes = $stmt2->execute();
                    
                    if($updateRes !== false){
                        $this->logSecurityEvent('mfa_code_sent', $userId, $username, 'MFA code sent to user email');
                        include "emails/MFAMessage.php";

                        $this->sendEmail($email, $subject, $message, $altMessage, $_SERVER['SERVER_NAME']);
                        
                        return array(
                            'error' => false,
                            'message' => "MFA code sent to your email.",
                            'userId' => $userId,
                            'username' => $username
                        );
                    }
                } else {
                    // Password incorrect - increment failed attempts
                    $failedAttempts = $row['failed_attempts'] ?? 0;
                    $failedAttempts++;
                    $lockUntil = null;
                    if ($failedAttempts >= 5) {
                        $lockUntil = date('Y-m-d H:i:s', time() + 3600); // Lock for 1 hour
                    }
                    $updateStmt = $con->prepare("UPDATE `accounts` SET `failed_attempts`=?, `locked_until`=? WHERE `userId`=?");
                    $updateStmt->bind_param('isi', $failedAttempts, $lockUntil, $userId);
                    $updateStmt->execute();
                    
                    $this->logSecurityEvent('login_failure', $userId, $username, "Invalid password. Failed attempts: $failedAttempts");
                }
            }
        }
        
        // Generic error message to prevent username enumeration
        if ($accountLocked) {
            return array(
                'error' => true,
                'message' => "Account locked due to too many failed attempts. Please try again later."
            );
        }
        return array(
            'error' => true,
            'message' => "Authentication failed."
        );
    }

    public function verifyMFA($userId, $code, $password = null, $username = null, $csrfToken = null, $trustDevice = false){
        // Rate limiting check per user
        if ($this->checkRateLimit('mfa_verify', (string)$userId, 5, 3600)) {
            $this->logSecurityEvent('rate_limit_blocked', $userId, $username, 'MFA verification blocked due to rate limiting');
            return array(
                'error' => true,
                'message' => "Too many MFA verification attempts. Please try again later."
            );
        }
        
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
            throw new Exception("Authentication service unavailable. Please try again later.");
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
                    
                    // Add device to trusted list if requested
                    if ($trustDevice) {
                        $this->addTrustedDevice($userId);
                    }
                    
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
            throw new Exception("Authentication service unavailable. Please try again later.");
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

