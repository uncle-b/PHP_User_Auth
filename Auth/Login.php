<?php include 'dbConnect.php';?>
<?php include 'JWT.php';?>
<?php

/*
Table: accounts
columns:
 - user
 - email
 - passToken
 - userId (auto increment value)
*/


$JSON = json_decode(file_get_contents('php://input'), true);

// $account = $JSON['account'];
$userName = $JSON['userName'];
// $email = $JSON['email'];
$password = $JSON['password'];

$passToken = base64_encode(hash_hmac('sha256', "$userName", $password, true));
$query = "SELECT * FROM `accounts` WHERE user='" . $userName . "';";

// $result = dbSingleResultQuery($query, "pass");
$result = dbQuery($query);
$row=mysqli_fetch_array($result,MYSQLI_ASSOC);
$res=$row['passToken'];


if($res==$passToken){
		
        // Password correct!
        $loginId =  random_str(32);
        $payload = array(
                "user" => $userName,
                "loginId" => $loginId,
                "issued" => time(),
                "expiry" => (time() + 31536000)  // = today + 1 year
                );

        $token = generateJWTHS256($payload, $key);
        
        header("Authorization: Value=Token token=$token");
        
        $result = array(
                'error' => false,
                'message' => "Login succesfull."
                );
        
        $loginIds = $row['loginId'];
        if($loginIds==""){
                $query = "UPDATE `accounts` SET `loginId`='$loginId' WHERE `user`='$userName';";
        } else {
                $loginIds .= "," . $loginId;
                $query = "UPDATE `accounts` SET `loginId`='$loginIds' WHERE `user`='$userName';";
        }
        
        dbQuery($query);
        
        echo(json_encode($result));
        
} else {
        $result = array(
                'error' => true,
                'message' => "Login failed."
        );
        
        echo(json_encode($result)); 
        
}

        

?>