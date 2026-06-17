<?php
header('Content-Type: application/json');
include "../Auth2.php";

// Start session for CSRF protection
$auth->startSession();

$JSON = json_decode(file_get_contents('php://input'), true);

$userName = isset($JSON['userName']) ? $JSON['userName'] : '';
$password = isset($JSON['password']) ? $JSON['password'] : '';
$csrfToken = isset($JSON['csrfToken']) ? $JSON['csrfToken'] : null;

if($userName === '' || $password === ''){
    $result = array(
        'error' => true,
        'message' => "Username and password are required."
    );
    echo json_encode($result);
    exit;
}

try{
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
