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

// Function to generate random token
function generate_token() {
    return bin2hex(random_bytes(16));
}

// Function to send authentication code via email or SMS
function send_authentication_code($method, $code) {
    // Code to send authentication code via email or SMS
    // Implement your email or SMS sending logic here
}

if($_SESSION['login'] != ''){
    $_SESSION['login'] = '';
}

if(isset($_POST['login'])) {
    // Sanitize input data
    $email = sanitize_input($_POST['emailid']);
    $password = $_POST['password'];

    // Prepare SQL statement with parameterized query
    $sql = "SELECT EmailId, Password, StudentId, Status, MFA FROM tblstudents WHERE EmailId = :email";
    $query = $dbh->prepare($sql);
    $query->bindParam(':email', $email, PDO::PARAM_STR);

    // Execute the query
    $query->execute();

    // Fetch the results
    $result = $query->fetch(PDO::FETCH_ASSOC);

    // Check if there are any results
    if($result) {
        if(password_verify($password, $result['Password'])) {
            // Check if MFA is enabled for the user
            if($result['MFA'] == 1) {
                // Generate and store authentication token
                $auth_token = generate_token();
                $_SESSION['auth_token'] = $auth_token;
                
                // Send authentication code via email or SMS
                send_authentication_code('email', $auth_token); // Change method based on user preference
                
                // Redirect to MFA verification page
                echo "<script type='text/javascript'> document.location ='mfa_verification.php'; </script>";
                exit();
            } else {
                // MFA not enabled, proceed with login
                $_SESSION['stdid'] = $result['StudentId'];
                if($result['Status'] == 1) {
                    $_SESSION['login'] = $email;
                    echo "<script type='text/javascript'> document.location ='dashboard.php'; </script>";
                    exit();
                } else {
                    echo "<script>alert('Your Account Has been blocked. Please contact admin');</script>";
                }
            }
        } else {
            echo "<script>alert('Invalid Password');</script>";
        }
    } else {
        echo "<script>alert('Invalid Email');</script>";
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>MFA Verification</title>
    <!-- Add your CSS styling here -->
</head>
<body>
    <h2>MFA Verification</h2>
    <?php if(isset($error)) { ?>
        <div><?php echo $error; ?></div>
    <?php } ?>
    <form method="post">
        <label for="token">Enter Authentication Code:</label><br>
        <input type="text" id="token" name="token" required><br><br>
        <input type="submit" name="verify" value="Verify">
    </form>
</body>
</html>
