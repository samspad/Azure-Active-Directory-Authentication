<?php 
    if(!isset($_SESSION)){
        session_start();
    }

    unset($_SESSION['user_id']);
    session_destroy();
    $return_url = "";
    if(isset($_GET['return_url'])){
        $return_url =$_GET['return_url'];
    }
    header("Location: login.php?return_url=$return_url");

?>