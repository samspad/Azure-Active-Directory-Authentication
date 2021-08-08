<?php
#### Login script for Simple Azure Oauth2 ####
#Session start
session_start();

#Remove from production version
error_reporting(-1);
ini_set("display_errors", "on");

/*Configuration, needs to match with Microsoft Azure Active Directory App registrations.
NOTE: Application needs to be create in "App Registrations" option and not in "Enterprise Applications"
Contact Systems Team for IDs required below:*/

#Application/client ID
$client_id = "________________";

#Tenant ID #Note: with Multitenant apps you can use "common" as Tenant ID, but using specific endpoint is recommended when possible
$ad_tenant = "________________";

#Client Secret #Note: remember that this expires someday unless you haven't set it not to do so
$client_secret = "________________";

#Redirect URL #Note: this needs to match 100% what is set in Azure
$redirect_uri = "________________";

#Send error to #Note: if php.ini doesn't contain sendmail_from, use: ini_set("sendmail_from", "user@example.com");
$error_email = "________________";

#Logout Redirect


function errorhandler($input, $email)
{

    $output = "PHP Session ID:    " . session_id() . PHP_EOL;
    $output .= "Client IP Address: " . getenv("REMOTE_ADDR") . PHP_EOL;
    $output .= "Client Browser:    " . $_SERVER["HTTP_USER_AGENT"] . PHP_EOL;
    $output .= PHP_EOL;
    #Capture output buffer
    ob_start();
    #Collect data for email
    var_dump($input);
    #Storing the output buffer content to $output
    $output .= ob_get_contents();
    ob_end_clean();
    // mb_send_mail($email, "Your Azure AD Oauth2 script faced an error!", $output, "X-Priority: 1\nContent-Transfer-Encoding: 8bit\nX-Mailer: PHP/" . phpversion());
    exit;
}

#var_dumps for debug purpose
if (isset($_GET["code"])) echo "<pre>";

#Authentication begins
if (!isset($_GET["code"]) and !isset($_GET["error"]))
{
    #Redirect (first load of this page)
    $url = "https://login.microsoftonline.com/" . $ad_tenant . "/oauth2/v2.0/authorize?";
    #State identifier
    $url .= "state=" . session_id();
    #Graph permission reference #Note: Also can try "&scope=profile+openid+email+offline_access+User.Read" depends on requirement
    $url .= "&scope=User.Read";
    $url .= "&response_type=code";
    $url .= "&approval_prompt=auto";
    $url .= "&client_id=" . $client_id;
    $url .= "&redirect_uri=" . urlencode($redirect_uri);
    #Redirect at Azure end
    header("Location: " . $url);

}

elseif (isset($_GET["error"]))
{
    echo "Error handler activated:\n\n";
    var_dump($_GET);
    #Debug print
    errorhandler(array(
        "Description" => "Error received at the beginning of second stage.",
        "\$_GET[]" => $_GET,
        "\$_SESSION[]" => $_SESSION
    ) , $error_email);
}

elseif (strcmp(session_id() , $_GET["state"]) == 0)
{
    #Checking session_id to match with state for security reasons
   // echo "Stage2:\n\n";
    #Debug print
    //var_dump($_GET);

    #Verifying the received tokens with Azure
    $content = "grant_type=authorization_code";
    $content .= "&client_id=" . $client_id;
    $content .= "&redirect_uri=" . urlencode($redirect_uri);
    $content .= "&code=" . $_GET["code"];
    $content .= "&client_secret=" . urlencode($client_secret);
    $options = array(
        #Use "http" even if you send the request with https
        "http" => array(
            "method" => "POST",
            "header" => "Content-Type: application/x-www-form-urlencoded\r\n" . "Content-Length: " . strlen($content) . "\r\n",
            "content" => $content
        )
    );

    $context = stream_context_create($options);
    $json = file_get_contents("https://login.microsoftonline.com/" . $ad_tenant . "/oauth2/v2.0/token", false, $context);
    if ($json === false) errorhandler(array(
        "Description" => "Error received during Bearer token fetch.",
        "PHP_Error" => error_get_last() ,
        "\$_GET[]" => $_GET,
        "HTTP_msg" => $options
    ) , $error_email);
    $authdata = json_decode($json, true);
    if (isset($authdata["error"])) errorhandler(array(
        "Description" => "Bearer token fetch contained an error.",
        "\$authdata[]" => $authdata,
        "\$_GET[]" => $_GET,
        "HTTP_msg" => $options
    ) , $error_email);
    
    #Debug print
    //var_dump($authdata);

    #Fetching the basic user information needed
    $options = array(
        "http" => array( //Use "http" even if you send the request with https
            "method" => "GET",
            "header" => "Accept: application/json\r\n" . "Authorization: Bearer " . $authdata["access_token"] . "\r\n"
        )
    );

    $context = stream_context_create($options);
    $json = file_get_contents("https://graph.microsoft.com/v1.0/me", false, $context);

    if ($json === false) errorhandler(array(
        "Description" => "Error received during user data fetch.",
        "PHP_Error" => error_get_last() ,
        "\$_GET[]" => $_GET,
        "HTTP_msg" => $options
    ) , $error_email);
    #Contains logged on user information
    $userdata = json_decode($json, true);

    if (isset($userdata["error"])) errorhandler(array(
        "Description" => "User data fetch contained an error.",
        "\$userdata[]" => $userdata,
        "\$authdata[]" => $authdata,
        "\$_GET[]" => $_GET,
        "HTTP_msg" => $options
    ) , $error_email);
    // print_r($userdata);
    $userID = $userdata['id'];
    #Azure group object ID validation
    $content = "{groupIds: ['______enter group id here from azure_____']}";
    $options = array(
        "http" => array(
            "method" => "GET",
            "header" => "Content-Type: application/json\r\n" . "Authorization: Bearer " . $authdata["access_token"] . "\r\n"
        )
    );

    #Fetching the basic user information needed
    $context = stream_context_create($options);
    $json = file_get_contents("https://graph.microsoft.com/v1.0/users/$userID/memberOf", false, $context);

    if ($json === false) errorhandler(array(
        "Description" => "Error received during user group data fetch.",
        "PHP_Error" => error_get_last() ,
        "\$_GET[]" => $_GET,
        "HTTP_msg" => $options
    ) , $error_email);
    #This should now contain logged on user memberOf (groups) information
    $groupdata = json_decode($json, true);

    if (isset($groupdata["error"])) errorhandler(array(
        "Description" => "Group data fetch contained an error.",
        "\$groupdata[]" => $groupdata,
        "\$authdata[]" => $authdata,
        "\$_GET[]" => $_GET,
        "HTTP_msg" => $options
    ) , $error_email);

    #Debug print
    //var_dump($groupdata);
    $groupAry = $groupdata['value'];
    #Azure group name validation
    $Groupvalidation = array_search("____enter group control here______", array_column($groupAry, "displayName"));
   // $Groupvalidation = array_search("f4e6235c-7ec5-450c-844d-5ca73db833a2", array_column($groupAry, "id"));


    if (isset($userdata['givenName']) && ($Groupvalidation != false))
    {
        extract($userdata);
        $_SESSION['email'] = $userPrincipalName;
        $_SESSION['is_pi'] = '';
        $_SESSION['account'] = $userPrincipalName;
        $_SESSION['user_id'] = $userPrincipalName;
        $_SESSION['user_name'] = $givenName;
        $msg = "Successful Login";

        #redirect after authentication
        $redirect = "______enter file name here_____";
        
		if (isset($return_url))
        {
			if ($return_url != "")
            $redirect = $return_url;
        }

        echo "

        <script>        
          window.location.href='../$redirect'
        </script>

        ";

    }

    else
    {
        #logout redirect
        $redirect = "______enter file name here_____";
        echo "

        <script>
        alert('you dont have access of group.');        
          window.location.href='../$redirect'
        </script>

        ";
    }

}
else
{
    #IMPORTANT: If you end up here, something has obviously gone wrong... Likely that the sent and returned state aren't matching and no $_GET["error"] received.
    echo "Hey, something has gone wrong!\n\n";
    echo "PHP Session ID used as state: " . session_id() . "\n";
    #var_dumps might be useful
    var_dump($_GET);
    errorhandler(array(
        "Description" => "Likely a state mismatch.",
        "\$_GET[]" => $_GET,
        "\$_SESSION[]" => $_SESSION
    ) , $error_email);
}
#Only to ease up your tests
echo "\n<a href=\"" . $redirect_uri . "\">Click here to redo the authentication</a>";
?>
