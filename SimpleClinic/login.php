<?php
session_start();
require_once 'db.php';

function log_audit($conn, $username, $role_attempted, $status) {
    $ip = $_SERVER['REMOTE_ADDR'];
    $stmt = $conn->prepare("INSERT INTO audit_log (username, role_attempted, status, ip_address) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("ssss", $username, $role_attempted, $status, $ip);
    $stmt->execute();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username']);
    $password = $_POST['password'];
    $selected_role = $_POST['selected_role'];

    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $res = $stmt->get_result();

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username']);
    $password = $_POST['password'];
    $selected_role = $_POST['selected_role'];

    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $res = $stmt->get_result();

    if ($res->num_rows > 0) {
        $user = $res->fetch_assoc();

        if (!is_null($user['locked_until']) && strtotime($user['locked_until']) > time()) {
            $status = "Locked Out";
            log_audit($conn, $username, $selected_role, $status);
            $remaining = round((strtotime($user['locked_until']) - time()) / 60);
            $error = "Account is locked. Try again in $remaining minute(s).";
        } elseif (password_verify($password, $user['password'])) {
            if ($user['role'] === $selected_role) {
                $reset = $conn->prepare("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?");
                $reset->bind_param("i", $user['id']);
                $reset->execute();

                log_audit($conn, $username, $selected_role, "Success");

                $_SESSION['user'] = $user;
                $_SESSION['last_active'] = time();
                header("Location: dashboard.php");
                exit;
            } else {
                log_audit($conn, $username, $selected_role, "Role Mismatch");
                $error = "Access Denied: You are not authorized to log in as a $selected_role.";
            }
        } else {
            $attempts = $user['failed_attempts'] + 1;
            $lock_time = NULL;

            if ($attempts >= 3) {
                $lock_time = date("Y-m-d H:i:s", strtotime("+5 minutes"));
                $error = "Account locked for 5 minutes due to multiple failed attempts.";
                $status = "Locked Out";
            } else {
                $error = "Incorrect password. Attempt $attempts of 3.";
                $status = "Failed Login";
            }

            $update = $conn->prepare("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?");
            $update->bind_param("isi", $attempts, $lock_time, $user['id']);
            $update->execute();

            log_audit($conn, $username, $selected_role, $status);
        }
    } else {
        log_audit($conn, $username, $selected_role, "User Not Found");
        $error = "User not found.";
    }
}
}
//CSS
?>
<!DOCTYPE html>
<html>
<head>
    <title>Login with Audit Logging</title>
    <link rel="stylesheet" href="style.css">
    <script>
        function setRole(role) {
            document.getElementById('selected_role').value = role;
            document.getElementById('login_form').submit();
        }
    </script>
</head>
<body>
<div class="container">
    <h2>Login</h2>
    <form method="post" id="login_form">
        <input type="text" name="username" required placeholder="Username">
        <input type="password" name="password" required placeholder="Password">
        <input type="hidden" name="selected_role" id="selected_role">
        <button type="button" onclick="setRole('Doctor')">Login as Doctor</button>
        <button type="button" onclick="setRole('Staff')">Login as Staff</button>
    </form>
    <p class="error"><?= isset($error) ? $error : '' ?></p>
    <?php if (isset($_GET['timeout'])) echo "<p class='error'>⚠️ Your session has expired due to inactivity. Please log in again.</p>"; ?>

</div>
</body>
</html>

