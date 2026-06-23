<?php 
header('Content-Type: application/json');
include "../Auth2.php";

$JSON = json_decode(file_get_contents('php://input'), true);
$redirectUrl = isset($JSON["redirectUrl"]) ? $JSON["redirectUrl"] : "/";
$onAllAccounts = isset($JSON["onAllAccounts"]) ? $JSON["onAllAccounts"] : false;

$res = $auth->signOut($onAllAccounts);

$result = ['error'=>true, 'message'=>'sign out failed.'];
if($res){
    
    $currentTime = time();
    $cookieOptions = [
        'expires' => $currentTime - 86400,
        'path' => '/',
        'domain' => '', // Current host only
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Strict'
    ];
    setcookie("X_AUTH_KEY", "", $cookieOptions);
    $result = ['error'=>false, 'message'=>'sign out completed'];
}

echo json_encode($result);
