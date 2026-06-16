<?php 
header('Content-Type: application/json');
include "../Auth2.php";

$JSON = json_decode(file_get_contents('php://input'), true);
$redirectUrl = isset($JSON["redirectUrl"]) ? $JSON["redirectUrl"] : "/";
$onAllAccounts = isset($JSON["onAllAccounts"]) ? $JSON["onAllAccounts"] : false;

$res = $auth->signOut($onAllAccounts);

$result = ['error'=>true, 'message'=>'sign out failed.'];
if($res){
    $result = ['error'=>false, 'message'=>'sign out completed'];
}

echo json_encode($result);
