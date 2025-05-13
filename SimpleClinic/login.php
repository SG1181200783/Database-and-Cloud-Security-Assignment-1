<?php
session_start();
require_once 'db.php';

function log_audit($conn, $username, $role_attempted, $status) {
    $ip = $_SERVER['REMOTE_ADDR'];
    $stmt = $conn->prepare("INSERT INTO audit_log (username, role_attempted, status, ip_address) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("ssss", $username, $role_attempted, $status, $ip);
    $stmt->execute();
}