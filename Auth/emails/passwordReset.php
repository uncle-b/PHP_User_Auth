<?php

//Set email subject:
$subject = "Password Reset Request";

ob_start(); ?>
<!DOCTYPE html>
<html>
    <head>
        
    </head>
    <body>
        
        You have requested to reset your password. Please click the link below to set a new password:<br><br>
        <a href="<?php echo $resetLink?>"><?php echo $resetLink?></a><br><br>
        This link will expire in 1 hour. If you did not request a password reset, please ignore this email.

    </body>
</html>
<?php 
    $message = ob_get_clean(); 
    ob_end_clean();

    //Set non html alt text.
    $altMessage = "You have requested to reset your password. Please visit the following URL to set a new password:\n";
    $altMessage.= $resetLink . "\n\n";
    $altMessage.= "This link will expire in 1 hour. If you did not request a password reset, please ignore this email.";
?>
