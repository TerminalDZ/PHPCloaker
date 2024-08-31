<?php

require_once("./Obfuscator.php");

use Obfuscator\Obfuscator;

try {
    $inputBasePath = 'public_html';
    $outputBasePath = 'obfuscated_html';

    $directoriesToObfuscate = [
        "$inputBasePath/app",
    ];

    $filesToObfuscate = [
        "$inputBasePath/index.php"
    ];

    $obfuscator = new Obfuscator($inputBasePath, $outputBasePath);
    $obfuscator->copyAndObfuscate($directoriesToObfuscate, $filesToObfuscate);

    echo "All specified files and directories have been obfuscated successfully.";
} catch (Exception $e) {
    echo $e->getMessage();
}