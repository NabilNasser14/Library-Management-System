<?php
session_start();
error_reporting(0);
include('includes/config.php');

// Function to sanitize input data
function sanitize_input($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $data;
}

// Function to encode output to prevent XSS attacks
function encode_output($data) {
    return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
}

// Function to log events
function log_event($event) {
    $log_file = 'security_log.txt';
    $event = date('Y-m-d H:i:s') . ' - ' . $event . PHP_EOL;
    file_put_contents($log_file, $event, FILE_APPEND | LOCK_EX);
}

if($_SESSION['alogin'] != ''){
    $_SESSION['alogin'] = '';
}

if(isset($_POST['login'])) {
    // Sanitize input data
    $username = sanitize_input($_POST['username']);
    $password = md5($_POST['password']); // Avoid using MD5 for password hashing, consider more secure methods like bcrypt

    // Prepare SQL statement with parameterized query
    $sql = "SELECT UserName, Password FROM admin WHERE UserName = :username AND Password = :password";
    $query = $dbh->prepare($sql);
    $query->bindParam(':username', $username, PDO::PARAM_STR);
    $query->bindParam(':password', $password, PDO::PARAM_STR);

    // Execute the query
    $query->execute();

    // Fetch the results
    $results = $query->fetchAll(PDO::FETCH_OBJ);

    // Check if there are any results
    if($query->rowCount() > 0) {
        $_SESSION['alogin'] = $username;
        // Log successful login
        log_event("Successful login by user: $username");
        echo "<script type='text/javascript'> document.location ='admin/dashboard.php'; </script>";
    } else {
        // Log failed login attempt
        log_event("Failed login attempt for username: $username");
        echo "<script>alert('" . encode_output('Invalid Details') . "');</script>";
    }
}
?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
    <meta name="description" content="" />
    <meta name="author" content="" />
    <title>Online Library Management System</title>
    <!-- BOOTSTRAP CORE STYLE  -->
    <link href="assets/css/bootstrap.css" rel="stylesheet" />
    <!-- FONT AWESOME STYLE  -->
    <link href="assets/css/font-awesome.css" rel="stylesheet" />
    <!-- CUSTOM STYLE  -->
    <link href="assets/css/style.css" rel="stylesheet" />
    <!-- GOOGLE FONT -->
    <link href='http://fonts.googleapis.com/css?family=Open+Sans' rel='stylesheet' type='text/css' />
</head>
<body>
    <?php include('includes/header.php');?>
    <div class="content-wrapper">
        <div class="container">
            <div class="row pad-botm">
                <div class="col-md-12">
                    <h4 class="header-line">ADMIN LOGIN FORM</h4>
                </div>
            </div>
            <div class="row">
                <div class="col-md-6 col-sm-6 col-xs-12 col-md-offset-3">
                    <div class="panel panel-info">
                        <div class="panel-heading">
                            LOGIN FORM
                        </div>
                        <div class="panel-body">
                            <form role="form" method="post">
                                <div class="form-group">
                                    <label>Enter Username</label>
                                    <input class="form-control" type="text" name="username" autocomplete="off" required />
                                </div>
                                <div class="form-group">
                                    <label>Password</label>
                                    <input class="form-control" type="password" name="password" autocomplete="off" required />
                                </div>
                                <button type="submit" name="login" class="btn btn-info">LOGIN</button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <?php include('includes/footer.php');?>
    <script src="assets/js/jquery-1.10.2.js"></script>
    <script src="assets/js/bootstrap.js"></script>
    <script src="assets/js/custom.js"></script>
</body>
</html>
