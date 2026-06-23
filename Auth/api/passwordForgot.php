<?php
header('Content-Type: application/json');
include "../Auth2.php";

// Start session for CSRF protection
$auth->startSession();

$JSON = json_decode(file_get_contents('php://input'), true);

$username = isset($JSON['username']) ? $JSON['username'] : '';
$csrfToken = isset($JSON['csrfToken']) ? $JSON['csrfToken'] : null;
$resetURL = isset($JSON['resetURL']) ? $JSON['resetURL'] : null;

if($username === ''){
    $result = array(
        'error' => true,
        'message' => "Username is required."
    );
    echo json_encode($result);
    exit;
}

try{
    $success = $auth->requestPasswordReset($username, $resetURL, $csrfToken);
    if($success === true){
        $result = array(
            'error' => false,
            'message' => "If an account exists with this username, a password reset link has been sent."
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
