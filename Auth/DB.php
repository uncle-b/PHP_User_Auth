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

	public static function query($connection, $query, $params = []){
		// Security: Disable raw query execution to prevent SQL injection
		// All queries should use prepared statements directly
		error_log("DEPRECATED: DB::query() with raw SQL is disabled. Use prepared statements directly.");
		return false;
	}

	public static function singleResultQuery($connection, $query, $column, $params = []){
		// Security: Disable raw query execution to prevent SQL injection
		error_log("DEPRECATED: DB::singleResultQuery() with raw SQL is disabled. Use prepared statements directly.");
		return false;
	}

	public static function escapeString($string){
		$con = dbConnect();
		$res = mysqli_real_escape_string($con, $string);
		dbDisconnect($con);
		return $res;
	}

}
?>