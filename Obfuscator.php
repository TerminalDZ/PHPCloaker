<?php

namespace Obfuscator;

use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use Exception;

class Obfuscator
{
    private string $sourcePath;
    private string $destPath;
    private string $keyDirPath;
    private array $keyFileNameMap = [];

    public function __construct(string $sourcePath, string $destPath, string $keyDirPath)
    {
        $this->sourcePath = rtrim(realpath($sourcePath), DIRECTORY_SEPARATOR);
        $this->destPath = rtrim($destPath, DIRECTORY_SEPARATOR);
        $this->keyDirPath = rtrim($keyDirPath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $this->generateRandomName();
        $this->createDirectory($this->keyDirPath); 
    }

    public function copyAndObfuscate(array $dirsToObfuscate, array $filesToObfuscate): void
    {
        $this->createOutputDirectory();
        $this->copyDirectory($this->sourcePath, $this->destPath);

        foreach ($dirsToObfuscate as $directory) {
            $this->obfuscateDirectory($directory);
        }

        foreach ($filesToObfuscate as $file) {
            $fileName = basename($file);
            $outputFilePath = $this->destPath . DIRECTORY_SEPARATOR . $fileName;
            $this->obfuscateFile($file, $outputFilePath);
        }
    }

    private function obfuscateFile(string $filePath, string $outputFilePath): void
    {
        $content = $this->prepareFileContent($filePath);
        $secretKey = $this->generateSecretKey();  
        $encryptedContent = $this->complexEncrypt($content, $secretKey); 
        $this->storeKey($filePath, $secretKey);
        $obfuscatedCode = $this->generateObfuscatedCode($encryptedContent, $filePath);

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

    private function storeKey(string $filePath, string $secretKey): void
    {
        $relativePath = $this->getRelativePath($filePath);
        $keyFileName = $this->generateFileHash($relativePath) . '.key';
        $keyFilePath = $this->keyDirPath . DIRECTORY_SEPARATOR . $keyFileName;

        if (file_put_contents($keyFilePath, $secretKey) === false) {
            throw new Exception("Error: Failed to write encryption key for {$relativePath}.");
        }

        $this->keyFileNameMap[$relativePath] = $keyFileName;
    }

    private function createOutputDirectory(): void
    {
        $this->createDirectory($this->destPath);
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
        return str_replace($this->sourcePath, '', $file);
    }

    private function getOutputFilePath(string $relativePath): string
    {
        return $this->destPath . DIRECTORY_SEPARATOR . ltrim($relativePath, DIRECTORY_SEPARATOR);
    }

    private function prepareFileContent(string $filePath): string
    {
        return "if (ob_get_length()) { ob_end_clean(); } ?>" . php_strip_whitespace($filePath);
    }

    private function complexEncrypt(string $data, string $secretKey): string
    {
        $compressedData = gzcompress($data, 9);
        $base64EncodedData = base64_encode($compressedData);

        $salt = bin2hex(random_bytes(16));
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('AES-256-CBC'));
        $encryptedData = openssl_encrypt($base64EncodedData, 'AES-256-CBC', $secretKey, 0, $iv);

        $finalCompressedData = gzcompress($salt . $iv . $encryptedData, 9);
        return base64_encode($finalCompressedData);
    }

    private function generateObfuscatedCode(string $encryptedData, string $filePath): string
    {
        $relativePath = $this->getRelativePath($filePath);
    
        if (!isset($this->keyFileNameMap[$relativePath])) {
            throw new Exception("Error: Key file name not found for {$relativePath}.");
        }
        $keyFilePath = $this->keyDirPath . DIRECTORY_SEPARATOR . $this->keyFileNameMap[$relativePath];
    
        $encryptedKeyFilePath = $this->encryptKeyPath($keyFilePath);
        
    
        $variable1 = $this->generateRandomName();
        $variable2 = $this->generateRandomName();
        $variable3 = $this->generateRandomName();
        $variable4 = $this->generateRandomName();
        $variable5 = $this->generateRandomName();
        $variable6 = $this->generateRandomName();
        $variable7 = $this->generateRandomName();
        $variable8 = $this->generateRandomName();
        $variable9 = $this->generateRandomName(); 
        $variable10 = $this->generateRandomName();
        $masterKey = $encryptedKeyFilePath['master'];
        $encryptedKeyFilePath = $encryptedKeyFilePath['key'];
    
        return <<<PHP
    <?php
    if (!ob_start()) {
        ob_start();
    }
    \$$variable1 = '$encryptedData';
    \$$variable2 = '$encryptedKeyFilePath';
    \$$variable10 = '$masterKey';
    \$$variable9 = openssl_decrypt(\$$variable2, 'AES-256-CBC', \$$variable10, 0, \$$variable10);
    \$$variable3 = file_get_contents(\$$variable9);
    \$$variable4 = gzuncompress(base64_decode(\$$variable1));
    \$$variable5 = substr(\$$variable4, 0, 32);
    \$$variable6 = substr(\$$variable4, 32, 16);
    \$$variable7 = substr(\$$variable4, 48);
    \$$variable8 = openssl_decrypt(\$$variable7, 'AES-256-CBC', \$$variable3, 0, \$$variable6);
    eval(gzuncompress(base64_decode(\$$variable8)));
    \$output = ob_get_contents();
    echo \$output;
    ?>
    PHP;
    }
    
    private function encryptKeyPath(string $keyFilePath): array
    {
        $masterKey = $this->generateMasterKey();
        
        $encryptedKeyFilePath = openssl_encrypt($keyFilePath, 'AES-256-CBC', $masterKey, 0, $masterKey);
        return ['key' => $encryptedKeyFilePath, 'master' => $masterKey];
    }
    

    private function writeObfuscatedFile(string $outputFilePath, string $obfuscatedCode): void
    {
        $outputDir = dirname($outputFilePath);
        $this->createDirectory($outputDir);

        if (file_put_contents($outputFilePath, $obfuscatedCode) === false) {
            throw new Exception("Error: Failed to write to the output file $outputFilePath.");
        }
    }

    private function generateSecretKey(): string
    {
        return base64_encode(openssl_random_pseudo_bytes(32));
    }

    private function createDirectory(string $path): void
    {
        if (!is_dir($path)) {
            mkdir($path, 0755, true);
        }
    }

    private function generateRandomName(): string
    {
        return 'IBA' . bin2hex(random_bytes(8));
    }

    private function generateFileHash(string $filePath): string
    {
        return hash('sha256', $filePath . random_bytes(16));
    }

    private function generateMasterKey(): string
    {
        return base64_encode(random_bytes(32));
    }
}
