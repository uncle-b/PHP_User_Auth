<?php
// Handle CORS preflight OPTIONS requests for all API endpoints
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';

    error_log("Preflight; origin = $origin");

    // Allow localhost, 127.0.0.1, and booth.localhost development origins (any port)
    if (preg_match('#^(http|https)://(localhost|127\.0\.0\.1|booth\.localhost)(:\d+)?$#i', $origin)) {
        header("Access-Control-Allow-Origin: $origin");
        header("Access-Control-Allow-Credentials: true");
        header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
        header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, X-Auth-Body-Token, X-CSRF-Token");
        header("Access-Control-Max-Age: 86400"); // Cache for 24 hours
    }

    // Always exit for OPTIONS
    http_response_code(204);
    exit;
} else {
    error_log("Preflight bypassed. Request method = ".$_SERVER['REQUEST_METHOD']);
}
