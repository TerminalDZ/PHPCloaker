<?php

require_once("./Obfuscator.php");

use Obfuscator\Obfuscator;

try {
    $sourceDir = 'public_html';
    $destinationDir = 'obfuscated_html';
    $keyDirectory = 'keys_storage';

    $dirsToObfuscate = [
        "$sourceDir/app",
    ];

    $filesToObfuscate = [
        "$sourceDir/index.php"
    ];

    $obfuscator = new Obfuscator($sourceDir, $destinationDir, $keyDirectory);
    $obfuscator->copyAndObfuscate($dirsToObfuscate, $filesToObfuscate);

    echo "All specified files and directories have been obfuscated successfully.";
} catch (Exception $e) {
    echo "An error occurred: " . $e->getMessage();
}