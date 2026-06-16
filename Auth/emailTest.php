<?php

// Note that this script is included for testing only and can be deleted before production release.
include "Auth2.php";

$auth->testEmail($_ENV["AUTH_SMTP_EMAIL"]);




