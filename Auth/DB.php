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

	public static function query($connection, $query){
		$result = mysqli_query($connection, $query) or die('Error:' . mysql_error());
		return $result;
	}

	public static function singleResultQuery($connection, $query, $column){
		$ret = "";		
		if($connection!==null){
			$result = mysqli_query($connection, $query);
			if(mysqli_num_rows($result)>0){	
				error_log("checkpoint 1");
				$row = mysqli_fetch_array($result);
				$ret = $row[$column];
				return $ret;
			} else {
				error_log("checkpoint 2");
				return false;
			}
			error_log("checkpoint 3");
			return $ret;
		}
	}

	public static function escapeString($string){
		$con = dbConnect();
		$res = mysqli_real_escape_string($con, $string);
		dbDisconnect($con);
		return $res;
	}

}
?>