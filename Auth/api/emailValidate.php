<?php
header('Content-Type: application/json');
include "../Auth2.php";

// Start session for CSRF protection
$auth->startSession();

$JSON = $auth->getRequestData();

$account = isset($JSON['account']) ? $JSON['account'] : '';
$key = isset($JSON['key']) ? $JSON['key'] : '';

$result = $auth->verifyAccount($account, $key);

if($result){
    $result = array(
            'error' => false,
            'message' => "Thank you for verifying your email address."
        );
    } else {
        $result = array(
            'error' => true,
            'message' => "Sorry, email verification failed."
        );
    }
    echo json_encode($result);
