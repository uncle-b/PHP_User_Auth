<?php

//Set email subject:
$subject = "Email validation";

ob_start(); ?>
<!DOCTYPE html>
<html>
    <head>
        
    </head>
    <body>

        Thank you for registering. Please click the below link to validate your email address:<br><br>
        <a href="<?php echo $validationURL?>"><?php echo $validationURL?></a>

    </body>
</html>
<?php 
    $message = ob_get_clean(); 
    ob_end_clean();

    //Set non html alt text.
    $altMessage = "Thank you for registering. Please visit the below url in your broser to verify your email address.\n";
    $altMessage.= $validationURL;
?>