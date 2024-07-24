<?php
session_start(); // Start the session at the beginning

// Initialize login feedback variable
$login_feedback = '';

// Set maximum login attempts and timeout period
$max_attempts = 3;
$timeout_duration = 10; // in seconds (10 seconds)

// Initialize session variables if not set
if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = 0;
    $_SESSION['last_attempt_time'] = 0;
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Check if the user is currently timed out
    if ($_SESSION['login_attempts'] >= $max_attempts && time() - $_SESSION['last_attempt_time'] < $timeout_duration) {
        $login_feedback = "Too many login attempts. Please wait 10 seconds before trying again.";
    } else {
        if (isset($_POST['email'], $_POST['password'], $_POST['g-recaptcha-response'])) {
            $email = $_POST['email'];
            $password = $_POST['password'];
            $recaptcha_response = $_POST['g-recaptcha-response'];

            // Verify reCAPTCHA response
            $recaptcha_secret = '6Le6hPApAAAAAJUc9RTeWMMhhuXQKLIW5JiiD-D9';
            $recaptcha_url = 'https://www.google.com/recaptcha/api/siteverify';
            $recaptcha_data = array(
                'secret' => $recaptcha_secret,
                'response' => $recaptcha_response
            );

            $options = array(
                'http' => array(
                    'method' => 'POST',
                    'header' => 'Content-type: application/x-www-form-urlencoded',
                    'content' => http_build_query($recaptcha_data)
                )
            );

            $context = stream_context_create($options);
            $verify = file_get_contents($recaptcha_url, false, $context);
            $captcha_success = json_decode($verify);

            if ($captcha_success->success) {
                // Database connection
                $conn = new mysqli('localhost', 'root', '', 'registration');

                if ($conn->connect_error) {
                    die("Connection failed: " . $conn->connect_error);
                }

                // Prepared statement to prevent SQL injection
                $sql = "SELECT * FROM users WHERE email=?";
                $stmt = $conn->prepare($sql);
                $stmt->bind_param("s", $email);
                $stmt->execute();
                $result = $stmt->get_result();

                if ($result->num_rows > 0) {
                    $row = $result->fetch_assoc();
                    if (password_verify($password, $row['password'])) {
                        // Successful login, reset login attempts and start a session
                        $_SESSION['login_attempts'] = 0;
                        session_regenerate_id(true); // Regenerate session ID to prevent session fixation
                        $_SESSION['user_id'] = $row['id'];
                        $_SESSION['username'] = $row['username'];
                        $_SESSION['email'] = $row['email'];
                        header("Location: welcome.php");
                        exit();
                    } else {
                        // Invalid password
                        $_SESSION['login_attempts']++;
                        $_SESSION['last_attempt_time'] = time();
                        $login_feedback = "Invalid email or password";
                    }
                } else {
                    // No user found with that email
                    $_SESSION['login_attempts']++;
                    $_SESSION['last_attempt_time'] = time();
                    $login_feedback = "Invalid email or password";
                }

                $stmt->close();
                $conn->close();
            } else {
                $login_feedback = "reCAPTCHA verification failed. Please try again.";
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <style>
        body {
            background: linear-gradient(135deg, #6e8efb, #a777e3);
            background-size: cover;
            background-position: center;
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background-color: rgba(255, 255, 255, 0.9);
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
    </style>
</head>
<body>
<div class="container">
    <div class="row justify-content-center">
        <div class="col-md-6">
            <h2 class="text-center mt-3">User Authentication</h2>
            <ul class="nav nav-tabs" id="myTab" role="tablist">
                <li class="nav-item" role="presentation">
                    <a class="nav-link active" id="login-tab" data-bs-toggle="tab" href="#login" role="tab" aria-controls="login" aria-selected="true">Login</a>
                </li>
                <li class="nav-item" role="presentation">
                    <a class="nav-link" id="register-tab" data-bs-toggle="tab" href="#register" role="tab" aria-controls="register" aria-selected="false">Register</a>
                </li>
            </ul>
            <div class="tab-content" id="myTabContent">
                <div class="tab-pane fade show active" id="login" role="tabpanel" aria-labelledby="login-tab">
                    <form action="login.php" method="post" class="mt-3" id="login-form">
                        <div class="mb-3">
                            <label for="login-email" class="form-label">Email</label>
                            <input type="email" class="form-control" id="login-email" name="email" required>
                        </div>
                        <div class="mb-3">
                            <label for="login-password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="login-password" name="password" required>
                        </div>
                        <div class="g-recaptcha" data-sitekey="6Le6hPApAAAAADpMir9lIoIH6YbCsoTMMwJDUdNx"></div>
                        <button type="submit" class="btn btn-primary w-100">Login</button>
                        <div class="text-center mt-2">
                            <a href="forgot_password.php">Forgot Password?</a>
                        </div>
                        <div id="login-feedback" class="mt-2 text-danger"><?php echo $login_feedback; ?></div>
                    </form>
                </div>
                <div class="tab-pane fade" id="register" role="tabpanel" aria-labelledby="register-tab">
                    <form action="insert.php" method="post" class="mt-3" id="register-form">
                        <div class="mb-3">
                            <label for="register-username" class="form-label">Username</label>
                            <input type="text" class="form-control" id="register-username" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label for="register-email" class="form-label">Email address</label>
                            <input type="email" class="form-control" id="register-email" name="email" required>
                        </div>
                        <div class="mb-3">
                            <label for="register-password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="register-password" name="password" required>
                        </div>
                        <div class="mb-3">
                            <label for="register-confirm-password" class="form-label">Confirm Password</label>
                            <input type="password" class="form-control" id="register-confirm-password" name="confirm_password" required>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Register</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
<script>
// Login form validation
document.getElementById('login-form').addEventListener('submit', function (e) {
    var emailInput = document.getElementById('login-email');
    var passwordInput = document.getElementById('login-password');

    // Check if email is pasted
    if (emailInput.value !== emailInput.value.trim() || passwordInput.value !== passwordInput.value.trim()) {
        e.preventDefault();
        alert('Email and password cannot contain leading or trailing spaces.');
        return;
    }
});

// Register form validation
document.getElementById('register-form').addEventListener('submit', function (e) {
    var password = document.getElementById('register-password').value;
    var confirmPassword = document.getElementById('register-confirm-password').value;

    if (password !== confirmPassword) {
        e.preventDefault();
        alert('Passwords do not match.');
    }

    // Check if email is pasted
    var emailInputs = document.querySelectorAll('#register-email, #register-confirm-password');
    emailInputs.forEach(function (input) {
        if (input.value !== input.value.trim()) {
            e.preventDefault();
            alert('Email and password cannot contain leading or trailing spaces.');
            return;
        }
    });

    // Check if email is the same as the previous one
    var prevEmail = localStorage.getItem('prevEmail');
    var currentEmail = document.getElementById('register-email').value.trim();
    if (prevEmail && prevEmail === currentEmail) {
        e.preventDefault();
        alert('You cannot use the same email address again.');
        return;
    }
    localStorage.setItem('prevEmail', currentEmail);
});
</script>
</body>
</html>
