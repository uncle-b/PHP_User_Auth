<?php
include "../../Auth/Auth2.php";

$authentic = $auth->authenticateRequest();

header("Content-type: application/json");

if($authentic){
    $userId = $auth->userId;
    $userName = $auth->username;
    echo json_encode(["error"=>false, "message"=>"This is some very secret information for your &#128064; only."]);
} else {
    echo json_encode(["error"=>true, "message"=>"Sorry, you are not authorized to see this."]);
}

