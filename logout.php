<?php 
    if(!isset($_SESSION)){
        session_start();
    }


    // ######## store loging logs logout time  #######
            /*  $date = date('Y-m-d H:i:s');
                $logid = $_SESSION['login_log_id'];
                $sect_ql ="		
                UPDATE [dbo].[login_logs] SET 			
                    [logout_time] = '$date'
                WHERE [login_log_id] = '$logid'   ";
                //echo  $sect_ql;

                $stmt = sqlsrv_query( $conn1, $sect_ql );
                if( $stmt === false) {
                    die( print_r( sqlsrv_errors(), true) );
                }*/

    /* ############ Logs End ###########3 */

    unset($_SESSION['user_id']);
    session_destroy();
    $return_url = "";
    if(isset($_GET['return_url'])){
        $return_url =$_GET['return_url'];
    }
    header("Location: login.php?return_url=$return_url");

?>