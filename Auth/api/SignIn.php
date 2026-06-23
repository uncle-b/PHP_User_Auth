<?php
header('Content-Type: application/json');
include "../Auth2.php";

// Start session for CSRF protection
$auth->startSession();

$JSON = json_decode(file_get_contents('php://input'), true);

$userName = isset($JSON['userName']) ? $JSON['userName'] : '';
$password = isset($JSON['password']) ? $JSON['password'] : '';
$csrfToken = isset($JSON['csrfToken']) ? $JSON['csrfToken'] : null;
$mfaCode = isset($JSON['mfa_code']) ? $JSON['mfa_code'] : null;
$userId = isset($JSON['userId']) ? $JSON['userId'] : null;
$trustDevice = isset($JSON['trustDevice']) ? $JSON['trustDevice'] : false;

if($userName === '' || $password === ''){
    $result = array(
        'error' => true,
        'message' => "Username and password are required."
    );
    echo json_encode($result);
    exit;
}

try{
    
    if($mfaCode){

        error_log("verifying MFA Code");

        $result = $auth->verifyMFA($userId, $mfaCode, $password, $userName, $csrfToken, $trustDevice);
        
        error_log(json_encode($result));
        
        if($result['error'] === false && isset($result['token'])){
            // MFA verified and login complete
            $cookie_name = "X_AUTH_KEY";
            $cookie_value = $result['token'];

            $https=false;
            if($auth->isSecure()){
                $https=true;
            };


            $arr_cookie_options = array (
                'expires' => 0, 
                'path' => '/', 
                'domain' => '', // Current host only
                'secure' => $https,     // or false
                'httponly' => true,    // or false
                'samesite' => 'Strict' // None || Lax  || Strict
                );

            //setcookie($cookie_name, $cookie_value, 0, "/", $_SERVER['SERVER_NAME'], $https, true); 
            setcookie($cookie_name, $cookie_value, $arr_cookie_options); 

            $bodyToken = $result['bodyToken'];
            
            // For JSON requests, return JSON response
            $auth->jsonResponse([
                'error' => false,
                'message' => 'Login successful',
                'token' => $result['token'],
                'bodyToken' => $bodyToken
            ]);
        } else {
            $mfaError = true;
            $mfaErrorMsg = $result['message'];
            $auth->jsonResponse(['error' => true, 'message' => $result['message']], 400);
        }

    } else {
        $result = $auth->initiateMFA($userName, $password, $csrfToken, true);

        error_log("Initiating MFA");


        error_log(json_encode($result));

        if($result['error'] === false && isset($result['token'])){
            // Login complete (trusted device - MFA was skipped, or direct signIn)
            $cookie_name = "X_AUTH_KEY";
            $cookie_value = $result['token'];
            $bodyToken = $result['bodyToken'];

            $https = false;
            if($auth->isSecure()){
                $https = true;
            }
            
            $arr_cookie_options = array (
                'expires' => 0, 
                'path' => '/', 
                'domain' => '', // Current host only
                'secure' => $https,
                'httponly' => true,
                'samesite' => 'Strict'
            );
            
            
            setcookie($cookie_name, $cookie_value, $arr_cookie_options);
            
            $auth->jsonResponse([
                'error' => false,
                'message' => 'Login successful (trusted device)',
                'token' => $result['token'],
                'bodyToken' => $bodyToken
            ]);


        } elseif($result['error'] === false && isset($result['userId'])){
            // Password correct, MFA code sent
            $mfaPending = true;
            $mfaUserId = $result['userId'];
            $mfaUsername = $result['username'];
            $mfaPassword = $password;
            // For JSON requests, return MFA pending state
            
            $auth->jsonResponse([
                'error' => false,
                'mfaPending' => true,
                'userId' => $result['userId'],
                'username' => $result['username'],
                'message' => 'MFA code sent to your email'
            ]);
        }
    }

    $result = $auth->signIn($userName, $password, $csrfToken);
    echo json_encode($result);
} catch (Exception $e) {
    error_log($e);
    $result = array(
        'error' => true,
        'message' => "An error occurred during login."
    );
    echo json_encode($result);
}
