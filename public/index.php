<?php

declare(strict_types=1);

$autoload = is_file(__DIR__ . '/bootstrap/autoload.php')
    ? __DIR__ . '/bootstrap/autoload.php'
    : dirname(__DIR__) . '/bootstrap/autoload.php';

require $autoload;

use App\Http\Kernel;

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$uri = $_SERVER['REQUEST_URI'] ?? '/buka/';
$headers = function_exists('getallheaders') ? (array) getallheaders() : [];
$rawBody = (string) file_get_contents('php://input');
$contentType = strtolower((string) ($_SERVER['CONTENT_TYPE'] ?? ''));
$decodedBody = ($rawBody !== '' && str_contains($contentType, 'json'))
    ? (array) json_decode($rawBody, true)
    : $_POST;

$response = Kernel::handle(
    method: $method,
    path: $uri,
    headers: $headers,
    query: $_GET,
    body: $decodedBody,
);

http_response_code($response['status']);
foreach ($response['headers'] as $name => $value) {
    header($name . ': ' . $value);
}
echo $response['body'];

