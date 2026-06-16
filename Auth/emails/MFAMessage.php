<?php

//Set email subject:
$subject = "Your MFA code";

ob_start(); ?>
<!DOCTYPE html>
<html>
    <head>
        
    </head>
    <body>

        Your Multi-Factor Authentication code is: <strong><?php echo $mfaCode ?></strong><br><br>This code will expire in 15 minutes.<br><br>

    </body>
</html>
<?php 
    $message = ob_get_clean(); 
    ob_end_clean();

    //Set non html alt text.
    $altMessage = "Your Multi-Factor Authentication code is: $mfaCode \nThis code will expire in 15 minutes.\n";

?>