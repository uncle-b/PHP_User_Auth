<?php
header('Content-Type: application/json');
include "../Auth2.php";

$JSON = json_decode(file_get_contents('php://input'), true);

$account = isset($JSON['account']) ? $JSON['account'] : '';
$token = isset($JSON['token']) ? $JSON['token'] : '';
$newPassword = isset($JSON['newPassword']) ? $JSON['newPassword'] : '';

if($account === '' || $token === '' || $newPassword === ''){
    $result = array(
        'error' => true,
        'message' => "Account ID, token, and new password are required."
    );
    echo json_encode($result);
    exit;
}

try{
    $result = $auth->resetPassword($account, $token, $newPassword);
    echo json_encode($result);
} catch (Exception $e) {
    error_log($e);
    $result = array(
        'error' => true,
        'message' => "An error occurred during password reset."
    );
    echo json_encode($result);
}
