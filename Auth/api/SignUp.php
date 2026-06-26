<?php
header('Content-Type: application/json');
include "../Auth2.php";

// Start session for CSRF protection
$auth->startSession();
$auth->sendSecurityHeaders();

$JSON = $auth->getRequestData();

$usr = isset($JSON['userName']) ? $JSON['userName'] : '';
$pwd = isset($JSON['password']) ? $JSON['password'] : '';
$eml = isset($JSON['email']) ? $JSON['email'] : '';
$csrfTokenPost = isset($JSON['csrfToken']) ? $JSON['csrfToken'] : null;
$validationUrl = isset($JSON['validationUrl']) ? $JSON['validationUrl'] : null;

$error = false;
$usrErrorMsg = "";


if($usr !== ""){
    if($auth->userExists($usr)!==false){
        $error = true;
        $auth->jsonResponse(['error' => true, 'message' => 'User name already in use. Please choose a different name.'], 400);
    }
}

if($pwd !== ""){
    if($auth->validatePassword($pwd)===false){
        $error = true;
        $auth->jsonResponse(['error' => true, 'message' => 'Password is not strong enough.'], 400);
    }
}

if($eml !== ""){
    if($auth->validateEmail($eml)===false){
        $auth->jsonResponse(['error' => true, 'message' => 'Email address seems invalid.'], 400);
    }
}

if($usr == "" || $pwd == "" || $eml == "" || $error == true){

    $csrfToken = $auth->generateCsrfToken();
    if($isJson) {
        if($usr == "" || $pwd == "" || $eml == "") {
            $auth->jsonResponse(['error' => true, 'message' => 'All fields are required.'], 400);
        } elseif (!$auth->validateCsrfToken($csrfTokenPost)) {
            $auth->jsonResponse(['error' => true, 'message' => 'Invalid CSRF token.'], 400);
        } else {
            $auth->jsonResponse(['error' => true, 'message' => 'Validation errors occurred.'], 400);
        }
    }
 
} else {

    //Check if username is available
    //CSRF already validated in the condition above - no need to recheck

    try{
        $res = $auth->createUser($usr, $eml, $pwd, $validationUrl, $csrfTokenPost);
        $auth->jsonResponse([
            'error' => false,
            'message' => 'Thanks for signing up. We have sent an email to verify your address. Please click the link in that email to activate your account.'
        ]);
    } catch (Exception $e) {
        error_log($e);
        $auth->jsonResponse(['error' => true, 'message' => 'An error occurred during signup.'], 500);
        die;
    }
}