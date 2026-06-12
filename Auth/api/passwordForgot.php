<?php
header('Content-Type: application/json');
include "../Auth2.php";

$JSON = json_decode(file_get_contents('php://input'), true);

$email = isset($JSON['email']) ? $JSON['email'] : '';

if($email === ''){
    $result = array(
        'error' => true,
        'message' => "Email is required."
    );
    echo json_encode($result);
    exit;
}

if($auth->validateEmail($email) === false){
    $result = array(
        'error' => true,
        'message' => "Invalid email address."
    );
    echo json_encode($result);
    exit;
}

try{
    $success = $auth->requestPasswordReset($email);
    if($success === true){
        $result = array(
            'error' => false,
            'message' => "If an account exists with this email address, a password reset link has been sent."
        );
    } else {
        $result = array(
            'error' => true,
            'message' => "Failed to process password reset request."
        );
    }
    echo json_encode($result);
} catch (Exception $e) {
    error_log($e);
    $result = array(
        'error' => true,
        'message' => "An error occurred during password reset request."
    );
    echo json_encode($result);
}
