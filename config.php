<?php

$dsn = '(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=_____________)(PORT=_____________))(CONNECT_DATA=(SID=_____________)))';
$username = "_____________";
$password = "_____________";



$conn_oracle = @oci_pconnect(
      $username,
      $password,
      $dsn
);
      // or die("Database is not currently running");

      if (!$conn_oracle){
             //  die(oci_error());

echo    $record_popup  ="
	<div class='alert alert-danger w-75 mx-auto text-center' style='position: fixed;
  z-index: 8008;
  top: 10px;
  left: 15%;'> <b> Alert </b>: Database is not currently running. We are working on the problem ! </div>
	";

      } 

             
?>
