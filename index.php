<?php
    include "Auth/Auth2.php"
?>
<!DOCTYPE html>
<html>
<body>
    <h1>Auth Test</h1>
    <?php echo $_ENV["AUTH_SETUP_COMPLETED"]; 
            echo getcwd();?>
</body>


</html>