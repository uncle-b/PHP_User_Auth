<?php
class DB{
	public static function connect($dbUser, $dbPassword, $db){

		// Create connection
		$con=mysqli_connect("localhost", $dbUser, $dbPassword, $db);

		// Check connection
		if (mysqli_connect_errno()) {
			error_log("Failed to connect to MySQL: " . mysqli_connect_error());
			return null;
		} else {
			return $con;
		}
	}

	public static function disconnect($connection){
		mysqli_close($connection);
	}

	public static function escapeString($string){
		$con = dbConnect();
		$res = mysqli_real_escape_string($con, $string);
		dbDisconnect($con);
		return $res;
	}

}
?>