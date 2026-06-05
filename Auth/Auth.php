<?php

/* 
 * class for handling JWT sessions
 * 
 * methods:
 * - creating JWT tokens v
 * - revoking JWT tokens v
 * - creating users v
 * - change and reset passwords v
 * 
 * 
 */

require_once 'dbSession.php';
require_once 'jwt.php';
require_once 'phpmailer/mailer.php';

/*
 * Sample code:
 * 
 * // New instance
 * $auth = new auth($serverKey, $initialization_vector);
 * 
 * // Get set of request verification tokens:
 * // Returns ["headerKey"=>$headerKey, "bodyKey"=>$bodyKey]
 * $csrfKeyPair = $auth->getRequestVerificationToken();
 * 
 * // Check set of request verification tokens:
 * // Returns true or false
 * $keyPairValid = checkRequestVerificationToken($headerKey, $bodyKey)
 * 
 * // Get authentication token for use in future requests
 * $token = getWebToken($account, $user, $password)
 * 
 * // Check authentication token before processing request
 * // Returns false on failure and JSON object with user data on success.
 * $tokenValid = validateWebToken($token)
 * 
 * 
 * 
 * 
 */



class auth{
    
   private $sKey = null;
   private $iv = null;
   private $dbSession;
   // private $acount = [];
   private $user = [];
   
   public function __construct($serverKey, $iv){
       $this->sKey = $serverKey ;
       $this->dbSession = new dbSession();
       $this->iv = $iv;
   }
   
   /*
   private function getAccount($accountName){
       $query = "SELECT * FROM `accounts` WHERE accountName='" . $accountName . "'";
       $result = $this->dbSession->query($query);
       $this->account = mysqli_fetch_array($result,MYSQLI_ASSOC);
   }
   */

    private function getUser($userName){
        $query = "SELECT * FROM `users` WHERE `user`='$userName';";
        $result = $this->dbSession->query($query);
        $this->user = mysqli_fetch_array($result,MYSQLI_ASSOC);
    }

    private function getUserById($userId){
        $query = "SELECT * FROM `users` WHERE `userId`=$userId";
        $result = $this->dbSession->query($query);
        $this->user = mysqli_fetch_array($result,MYSQLI_ASSOC);
    }
   
   private function makePassToken($user, $password){
       return base64_encode(hash_hmac('sha256', "$user", $password, true));
   }
   
   private function isBlocked(){
       
       $blocked = true;
       
       if($this->user!=null){
           $failedAttempts = explode(",", $this->user["failedAttempts"]);
           if(sizeof($failedAttempts)>9){
               
               $lastAttempt = $failedAttempts[sizeof($failedAttempts)-1];
               if(($lastAttempt + (60*10)) < time()){
                    // Locked for more then 10 minutes. Reset failed attempts.
                   $blocked = false;
                } 
           } else {
               // Not yet blocked
               $blocked = false;
           }
       }
       
       return $blocked;
   }
   
   private function getLoginId(){
       
       $randStr = jwt::random_str(32);
       $expiry = time() + 31536000;  // = today + 1 year
       
       $loginId = base64_encode("$randStr.$expiry"); 
       
       $loginIds = $this->user["loginId"];
       if($loginIds==""){
                $query = "UPDATE `users` SET `loginId`='$loginId', `failedAttempts`='' WHERE `user`='".$this->user["user"]."';";
       } else {
                $loginIds .= "," . $loginId;
                $query = "UPDATE `users` SET `loginId`='$loginIds', `failedAttempts`='' WHERE `user`='".$this->user["user"]."';";
       }
       $this->dbSession->query($query);
       return $loginId;
       
   }
   
   public function revokeLoginId($user, $loginId){
       
       $query = "SELECT `loginId` FROM `users` WHERE `user`='$user'"; 
       $res = $this->dbSession->query($query);
       $userData = mysqli_fetch_array($res,MYSQLI_ASSOC);
       $loginIds = explode(",",$userData["loginId"]);
       
       for($i=0; $i<sizeof($loginIds); $i++) {
           if($loginIds[$i]==$loginId){
               array_splice($loginIds, $i, 1);
               break;
           }
       }

       $loginIds = implode(",",$loginIds);
       $query2 = "UPDATE `users` SET `loginId`='$loginIds' WHERE `user`='$user'";
       
       $res2 = $this->dbSession->query($query2);
   }
   
   private function validateLoginId($user, $loginId){

       $query = "SELECT * FROM `users` WHERE `user`='$user' AND `loginId` LIKE '%$loginId%' LIMIT 1";
       $res = $this->dbSession->query($query);
       if(mysqli_num_rows($res)>0){
            // double check the loginId
            // without this check a random single charachter as loginId may already give access.
            $userData = mysqli_fetch_array($res,MYSQLI_ASSOC);
            $loginIds = explode(",", $userData["loginId"]);
            if(array_search($loginId, $loginIds, false)!==false){ // array_search only returns exact match.
                return true;
            }
            return false;
       } else {
           return false;
       }
       
   }
   
   private function getAPIKeyId(){
    
    // Clone of getLoginId function, but with longer expiration time
    $randStr = jwt::random_str(32);
    $expiry = time() + (31536000*50);  // = today + 50 years
    
    $loginId = base64_encode("$randStr.$expiry"); 
    
    $loginIds = $this->user["ApiId"];

    if($loginIds==""){
             $query = "UPDATE `users` SET `ApiId`='$loginId' WHERE `user`='".$this->user["user"]."';";
    } else {
             $loginIds .= "," . $loginId;
             $query = "UPDATE `users` SET `ApiId`='$loginIds' WHERE `user`='".$this->user["user"]."';";
    }

    $this->dbSession->query($query);

    return $loginId;
    
    }



   
   
   
    private function regFailedAttempt(){
       $attempts = explode(",", $this->user["failedAttempts"]);
       array_push($attempts, (string) time());
       $attempts = implode(",", $attempts);
       $query = "UPDATE `users` SET `failedAttempts`='$attempts' WHERE `user`='" . $this->user["user"] . "'";
       $this->dbSession->query($query);
   }
   
   public function revokeAPIKeyId($user, $loginId){
       
    $query = "SELECT `ApiId` FROM `users` WHERE `user`='$user'"; 
    $res = $this->dbSession->query($query);
    $userData = mysqli_fetch_array($res,MYSQLI_ASSOC);
    $loginIds = explode(",",$userData["ApiId"]);
    
    for($i=0; $i<sizeof($loginIds); $i++) {
        if($loginIds[$i]==$loginId){
            array_splice($loginIds, $i, 1);
            break;
        }
    }

    $loginIds = implode(",",$loginIds);
    $query2 = "UPDATE `users` SET `ApiId`='$loginIds' WHERE `user`='$user'";
    $res2 = $this->dbSession->query($query2);
    }


   
   
    private function clearFailedAttempts(){
       if($this->user["failedAttempts"]!=""){
            $query = "UPDATE `users` SET `failedAttempts`='' WHERE `user`='" . $this->user["user"] . "'";
            $this->user["failedAttempts"] = '';
            $this->dbSession->query($query); 
       }
   }
   
   private function validateAPIKeyId($user, $loginId){

    $query = "SELECT * FROM `users` WHERE `user`='$user' AND `ApiId` LIKE '%$loginId%' LIMIT 1";
    $res = $this->dbSession->query($query);
    if(mysqli_num_rows($res)>0){
         // double check the loginId
         // without this check a random single charachter as loginId may already give access.
         $userData = mysqli_fetch_array($res,MYSQLI_ASSOC);
         $loginIds = explode(",", $userData["ApiId"]);
         if(array_search($loginId, $loginIds, false)!==false){ // array_search only returns exact match.
             return true;
         }
         return false;
    } else {
        return false;
    }
    }



   
    public function getRequestVerificationToken(){
       
       // For protection against CSRF attacks.
       // CSRF = Cross-Site Request Forgery
       // *********************************
       // HeaderKey to be provided in Header as secure cookie
       // BodyKey to be provided in request body
       // When checked with each other they 
       
       $shared = jwt::random_str(32);
       $headerKey = jwt::random_str(32);
       $bodyKey = jwt::random_str(32);
       
       $cypherMethod = 'AES-256-CBC';
       // $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($cypherMethod));
       
       
       $key1 = openssl_encrypt("$shared.$headerKey", $cypherMethod, $this->sKey, $options=0, $this->iv);
       $key2 = openssl_encrypt("$shared.$bodyKey", $cypherMethod, $this->sKey, $options=0, $this->iv);
       
       return ["headerKey"=>$key1, "bodyKey"=>$key2];
       
   }
   
   public function checkRequestVerificationToken($headerKey, $bodyKey){
       
       $cypherMethod = 'AES-256-CBC';
       $key1 = explode(".",openssl_decrypt($headerKey, $cypherMethod, $this->sKey, $options=0, $this->iv));
       $key2 = explode(".",openssl_decrypt($bodyKey, $cypherMethod, $this->sKey, $options=0, $this->iv));
       
       // if(($key1[0]==$key2[0]) && ($headerKey != $bodyKey)){
       if(hash_equals($key1[0], $key2[0]) && ($headerKey != $bodyKey)){
           return true;
       } else {
           return false;
       }
       
   }
   
   public function getWebToken($user, $password){
       
       $passToken = null;
       // $this->getAccount($account);
       // if($this->account != null){
           $this->getUser($user);
           if($this->user != null){
                 $passToken = $this->makePassToken($this->user["user"], $password);
           }
       // }
       
       if(!$this->isBlocked()){
           if($this->user["passToken"] == $passToken){
               $loginId = $this->getLoginId();
               $payload = array(
                    // "account" => $this->account["accountName"],
                    // "accountId" => $this->account["accountId"],
                    "userId"=> $this->user["userId"],
                    "user" => $this->user["user"],
                    "permissions" => ["all"],
                    "loginId" => $loginId,
                    "issued" => time(),
                    "expiry" => (time() + 31536000)  // = today + 1 year
                    );
               
                $token = jwt::generateJWTHS256($payload, $this->sKey);
                $this->clearFailedAttempts();
                
                return ['error' => false,
                        'message' => 'Permission granted',
                        'content' => ["token"=>$token,
                                    "header"=>"Set-Cookie: access_token=".$token."; Secure; HttpOnly;"]];
                
           } else {
               $this->regFailedAttempt();
               return ['error' => true,
                        'message' => 'Invalid credentials',
                        'content' => []];
           }
       } else {
           return ['error' => true,
                   'message' => 'User blocked',
                   'content' => []];
       }  
   }
   
   public function validateWebToken($token){
       
       //By default token is not trusted
       $requestValidated = false;
       
       // check validity of token and sustract payload
       $payload = jwt::checkJWTHS256($token, $this->sKey);
       
       if($payload!=false){

            // JSON Web token is valid.
            // convert payload to json opbject
            $userData = json_decode($payload, true);
            $loginIdValid = $this->validateLoginId($userData["user"], $userData["loginId"]);

            // Check if the token has not expired and if the login Id still exists (is not revoked).
            if(time() < $userData['expiry'] && $loginIdValid){
                $requestValidated = $userData;
                
                // Set $this->account & $this->user for methods te follow.
                // $this->getAccount($userData["account"]);
                $this->getUser($userData["user"]);
                $userData["userId"]= $this->user["userId"];          


            } else { // Token has expired or was revoked
                if($loginIdValid){ // Token expired
                    $this->revokeLoginId($userData["user"], $userData["loginId"]);
                }
            }
       }
       return $requestValidated;
       
   }
   
   public function getAPIKey($userData, $permissions, $description, $keyName="No_name"){
       
    $this->getUser($userData["user"]);
    
    if(!$this->isBlocked()){

            $description = htmlentities($description);
            $keyName = htmlentities($keyName);

            $loginId = $this->getAPIKeyId();
            $payload = array(
                 "userId"=> $this->user["userId"],
                 "user" => $this->user["user"],
                 "permissions" => $permissions,
                 "ApiKeyId" => $loginId,
                 "issued" => time(),
                 "expiry" => (time() + (31536000*50))  // = today + 50 years
                 );
            
             $token = jwt::generateJWTHS256($payload, $this->sKey);
             
             
             $query = "INSERT INTO `APIKeys`(`userId`, `APIKeyId`, `permissions`, `name`, `description`) VALUES (".$this->user["userId"].",'$loginId', '". implode(",",$permissions)."', '$keyName', '$description')";
             $this->dbSession->query($query);

             return ['error' => false,
                     'message' => 'Api Key generated',
                     'content' => ["APIKey"=>$token]];
             
    } else {
        return ['error' => true,
                'message' => 'User blocked',
                'content' => []];
    }  
}

   public function validateAPIKey($token){
       
    //By default token is not trusted
    $requestValidated = false;
    
    // check validity of token and subtract payload
    $payload = jwt::checkJWTHS256($token, $this->sKey);
    
    if($payload!=false){
         // JSON Web token is valid.
         // convert payload to json opbject
         $userData = json_decode($payload, true);
         $loginIdValid = $this->validateAPIKeyId($userData["user"], $userData["ApiKeyId"]);

         // Check if the token has not expired and if the login Id still exists (is not revoked).
         if(time() < $userData['expiry'] && $loginIdValid){
             
             $requestValidated = $userData;
             
             // Set $this->account & $this->user for methods te follow.
             // $this->getAccount($userData["account"]);
             // $this->getUser($userData["user"]);
             // $userData["userId"]= $this->user["userId"];          


         } else { // Token has expired or was revoked
             if($loginIdValid){ // Token expired
                 $this->revokeApiId($userData["user"], $userData["loginId"]);
             }
         }
    }
    return $requestValidated;
    
    }

    public function userExists($userName){
        $q1 = "SELECT * FROM `users` WHERE `user`='$userName' LIMIT 1;";
        $result = $this->dbSession->query($q1);
        $resultCnt = mysqli_num_rows($result);
           
        if(!$resultCnt){
            //User does not exist.
            return false;
        }
        return true;
    }


    public function newUser($userName, $password, $email){
       // Can only make new users for current account.
          
           $q1 = "SELECT * FROM `users` WHERE `user`='$userName' LIMIT 1;";
           $result = $this->dbSession->query($q1);
           $resultCnt = mysqli_num_rows($result);
           
           if(!$resultCnt){
               //User does not exist. Create it.
               $passToken = $this->makePassToken($userName, $password);
               
               $q2 = "INSERT INTO `users`(`user`, `passToken`, `email`, `loginId`, `permissions`, `failedAttempts`) "
                               . "VALUES ('$userName','$passToken','$email','','','')";
               
               
               $userId  = $this->dbSession->insertQuery($q2);
               
               return true;
               
            } else {
                return false;
            }
           
   }
   
   public function changePassword($userId, $newPassword, $validationKey, $signOutOnAll=false){

        $query = "SELECT * FROM `pendingRequests` WHERE `userId`=$userId AND `validationKey`='$validationKey'";
        $res = $this->dbSession->query($query);
            if(mysqli_num_rows($res)>0){
                $row = mysqli_fetch_array($res,MYSQLI_ASSOC);
                if($row['expiry']>time() && $row['action'] === 'resetPassword'){
                    // Validation key is valid, matches the userId and has not expired.
                    // Action associated to validation key is indeed for password change.
                            // $res = $this->auth->changePassword($userId, $newPassword);
                            $this->getUserById($userId);
                            $passToken = $this->makePassToken($this->user["user"], $newPassword);
                            $query = "UPDATE `users` SET `passToken`='$passToken' WHERE `userId`=$userId";
                            $res = $this->dbSession->updateQuery($query);
                            $query2 = "DELETE FROM `pendingRequests` WHERE `validationKey`='$validationKey' AND `userId`=$userId";
                            $res = $this->dbSession->query($query);
                            if($signOutOnAll){
                                $query3 = "UPDATE `users` SET `loginId`='' WHERE `userId`=$userId";
                                $res = $this->dbSession->updateQuery($query3);
                            }
                            return  ["error"=>false, "message"=>"Password sucessfully changed", "content"=>[]];
                    } else {
                       return ["error"=>true, "message"=>"Invalid request or validation key expired", "content"=>[]];
                    }
            } else {
                    return ["error"=>true, "message"=>"Invalid request", "content"=>[]];
            }
   }


   /*
   public function changePassword($oldPassword, $newPassword){
       
       if(sizeof($this->user) > 0){
           
           // Check old password:
           $oldPassToken = $this->makePassToken($this->user["user"], $oldPassword);
           $q = "SELECT `passToken` FROM `users` WHERE"
                   . " `user`='".$this->user["user"]."' AND `passToken`='$oldPassToken'";
           
           $res = $this->dbSession->query($q);
           
           if(mysqli_num_rows($res)>0){
                //oldPassword correct
               $newPasstoken = $this->makePassToken($this->user["user"], $newPassword);
               $q2 = "UPDATE `users` SET `passToken`='$newPasstoken' WHERE"
                   . " `user`='".$this->user["user"]."'";
               $res2 = $this->dbSession->query($q2);
               return true;
               
           } else {
               return false;
           }
           
       } else {
           return false;
       }
   }
   */
   
   public function resetPasswordLink($user){

    // $this->getAccount($account);
       
    // if(sizeof($this->account)>0){

           error_log("user=$user");
           $this->getUser($user);
           if($this->user !== null && sizeof($this->user)>0){
            
                $validationKey = jwt::random_str(64);
                $expiry = time() + (10*60);  // = now + 10 minutes
                $userId = $this->user["userId"];
                $action = "resetPassword";

                // $query = "INSERT INTO `passwordResets`(`user`,`validationKey`, `expiry`) VALUES ('$user','$validationKey', $expiry)";
                $query = "INSERT INTO `pendingRequests`(`userId`, `validationKey`, `expiry`, `action`) ";
                $query.= " VALUES ('$userId','$validationKey','$expiry','$action')";
                $this->dbSession->query($query);

                // $link = "account=".rawurlencode($account);
                // $link .= "user=".rawurlencode($user);
                // $link .= "&validationKey=".rawurlencode($validationKey);

                $link = "$userId/$validationKey";
                return ["email"=>$this->user["email"], "link"=>$link, "user"=>$this->user["user"]];
                
           } else {
               return false;
           }
           
       // } else {
       //    return false;
       // }


   }


   

   /*
   public function resetPassword($user){
       
       // $this->getAccount($account);
       
       // if(sizeof($this->account)>0){
        
           $this->getUser($user);
           if(sizeof($this->user)>0){
            
                $tmpPassword = jwt::random_str(8);
                $tmpPassToken = $this->makePassToken($user, $tmpPassword);
                $query = "UPDATE `users` SET `passToken`='$tmpPassToken' WHERE `user`='$user'"; 
                $this->dbSession->query($query);
                
                return ["email"=>$this->user["email"], "Password"=>$tmpPassword];
                
           } else {
               return false;
           }
        
       // } else {
       //     return false;
       // }
       
   }
   */
   


   public function verifyPassword($user, $password){
        $tmpPassToken = $this->makePassToken($user, $password);
        $query = "SELECT * FROM `users` WHERE `user`='$user' AND `passToken`='$tmpPassToken'";
        $res = $this->dbSession->query($query);
        if(mysqli_num_rows($res)>0){
            //oldPassword correct
            return true;
        }
        return false;
    }

    public function changeEmailLink($user, $newEmail){

               $this->getUser($user);
               if(sizeof($this->user)>0){
                
                    $newEmailEsc = $this->dbSession->escapeString($newEmail);
                    $validationKey = jwt::random_str(64);
                    $expiry = time() + (10*60);  // = now + 10 minutes
                    $query = "INSERT INTO `pendingRequests`(`userId`, `validationKey`, `expiry`, `action`, `parameters`) VALUES ('".$this->user["userId"]."','$validationKey', $expiry, 'changeEmailRequestValidation', '$newEmailEsc')";
                    error_log($query);
                    $this->dbSession->query($query);
    
                    // $link = "account=".rawurlencode($account);
                    $link .= "userId=".rawurlencode($this->user["userId"]);
                    $link .= "&validationKey=".rawurlencode($validationKey);
    
                    return ["email"=>$this->user["email"], "link"=>$link];
                    
               } else {
                   return false;
               }
       }
   
   
}

