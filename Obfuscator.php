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

    /**
     * Copy and obfuscate specified directories and files.
     *
     * @param array $directoriesToObfuscate
     * @param array $filesToObfuscate
     * @throws Exception
     */
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

    /**
     * Obfuscate a single file.
     *
     * @param string $filePath
     * @param string $outputFilePath
     * @throws Exception
     */
    public function obfuscateFile(string $filePath, string $outputFilePath): void
    {
        $data = $this->prepareFileContent($filePath);
        $encodedData = $this->encodeData($data);
        $obfuscatedCode = $this->generateObfuscatedCode($encodedData);

        $this->writeObfuscatedFile($outputFilePath, $obfuscatedCode);
    }

    /**
     * Obfuscate all PHP files in a directory.
     *
     * @param string $directory
     * @throws Exception
     */
    public function obfuscateDirectory(string $directory): void
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

    private function encodeData(string $data): string
    {
        $compressedData = gzcompress($data, 9);
        return base64_encode($compressedData);
    }

    private function generateObfuscatedCode(string $encodedData): string
    {
        return <<<PHP
<?php
ob_start();
\$data = '$encodedData';
eval(gzuncompress(base64_decode(\$data)));
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
}