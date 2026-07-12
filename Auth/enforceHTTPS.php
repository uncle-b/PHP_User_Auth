<?php

/**********************************************************************************************
 * WARNING: setting the below $auth_muteSetup variable to TRUE will bypass HTTPS requirement. *
 * This option exists for development purposes only and should NEVER be used in production    *
 * environments.                                                                              *
 **********************************************************************************************/

$auth_muteSetup = true; //Set this value to true to bypass https requirement.

if($auth_muteSetup == true){
    error_log("WARNING: You are currently bypassing HTTPS encryption. This is not safe for production environments. See /Auth/enforceHTTPS.php to change this setting.");
}