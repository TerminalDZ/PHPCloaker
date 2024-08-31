<?php

namespace Obfuscator;

use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use Exception;

class Obfuscator
{
    private string $inputPath;
    private string $outputPath;

    public function __construct(string $inputPath, string $outputPath)
    {
        $this->inputPath = rtrim(realpath($inputPath), DIRECTORY_SEPARATOR);
        $this->outputPath = rtrim($outputPath, DIRECTORY_SEPARATOR);
    }

    public function copyAndObfuscate(array $directoriesToObfuscate, array $filesToObfuscate): void
    {
        $this->createOutputDirectory();
        $this->copyDirectory($this->inputPath, $this->outputPath);

        foreach ($directoriesToObfuscate as $directory) {
            $this->obfuscateDirectory($directory);
        }

        foreach ($filesToObfuscate as $file) {
            $relativePath = $this->getRelativePath($file);
            $outputFilePath = $this->getOutputFilePath($relativePath);
            $this->obfuscateFile($file, $outputFilePath);
        }
    }

    private function obfuscateFile(string $filePath, string $outputFilePath): void
    {
        $data = $this->prepareFileContent($filePath);
        $encryptionKey = $this->generateEncryptionKey();
        $encodedData = $this->multiLayerEncrypt($data, $encryptionKey);
        $obfuscatedCode = $this->generateObfuscatedCode($encodedData, $encryptionKey);

        $this->writeObfuscatedFile($outputFilePath, $obfuscatedCode);
    }

    private function obfuscateDirectory(string $directory): void
    {
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory));
        foreach ($files as $file) {
            if ($file->isDir() || $file->getExtension() !== 'php') {
                continue;
            }

            $relativePath = $this->getRelativePath($file->getRealPath());
            $outputFilePath = $this->getOutputFilePath($relativePath);

            $this->obfuscateFile($file->getRealPath(), $outputFilePath);
        }
    }

    private function createOutputDirectory(): void
    {
        if (!is_dir($this->outputPath)) {
            mkdir($this->outputPath, 0755, true);
        }
    }

    private function copyDirectory(string $src, string $dst): void
    {
        $dir = opendir($src);
        @mkdir($dst);

        while (($file = readdir($dir)) !== false) {
            if (($file != '.') && ($file != '..')) {
                $srcPath = $src . DIRECTORY_SEPARATOR . $file;
                $dstPath = $dst . DIRECTORY_SEPARATOR . $file;

                if (is_dir($srcPath)) {
                    $this->copyDirectory($srcPath, $dstPath);
                } else {
                    copy($srcPath, $dstPath);
                }
            }
        }
        closedir($dir);
    }

    private function getRelativePath(string $file): string
    {
        return str_replace($this->inputPath, '', $file);
    }

    private function getOutputFilePath(string $relativePath): string
    {
        return $this->outputPath . DIRECTORY_SEPARATOR . ltrim($relativePath, DIRECTORY_SEPARATOR);
    }

    private function prepareFileContent(string $filePath): string
    {
        return "if (ob_get_length()) { ob_end_clean(); } ?>" . php_strip_whitespace($filePath);
    }

    private function multiLayerEncrypt(string $data, string $encryptionKey): string
    {
        // First layer: Compression and Base64 encoding
        $compressedData = gzcompress($data, 9);
        $base64EncodedData = base64_encode($compressedData);

        // Second layer: AES encryption with a unique key and salt
        $salt = bin2hex(random_bytes(16));
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('AES-256-CBC'));
        $encryptedData = openssl_encrypt($base64EncodedData, 'AES-256-CBC', $encryptionKey, 0, $iv);

        // Third layer: Further compression and Base64 encoding
        $finalCompressedData = gzcompress($salt . $iv . $encryptedData, 9);
        return base64_encode($finalCompressedData);
    }

    private function generateObfuscatedCode(string $encodedData, string $encryptionKey): string
    {
        return <<<PHP
<?php
ob_start();
\$data = '$encodedData';
\$decodedData = gzuncompress(base64_decode(\$data));
\$salt = substr(\$decodedData, 0, 32);
\$iv = substr(\$decodedData, 32, 16);
\$encryptedData = substr(\$decodedData, 48);
\$key = '$encryptionKey';
\$decryptedData = openssl_decrypt(\$encryptedData, 'AES-256-CBC', \$key, 0, \$iv);
eval(gzuncompress(base64_decode(\$decryptedData)));
\$output = ob_get_contents();
ob_end_clean();
echo \$output;
?>
PHP;
    }

    private function writeObfuscatedFile(string $outputFilePath, string $obfuscatedCode): void
    {
        $outputDir = dirname($outputFilePath);
        if (!is_dir($outputDir)) {
            mkdir($outputDir, 0755, true);
        }

        if (file_put_contents($outputFilePath, $obfuscatedCode) === false) {
            throw new Exception("Error: Failed to write to the output file $outputFilePath.");
        }
    }

    private function generateEncryptionKey(): string
    {
        return base64_encode(openssl_random_pseudo_bytes(32));
    }
}
