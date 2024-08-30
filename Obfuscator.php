<?php

class Obfuscator {
    private $inputPath;
    private $outputPath;

    public function __construct($inputPath, $outputPath) {
        $this->inputPath = rtrim(realpath($inputPath), DIRECTORY_SEPARATOR);
        $this->outputPath = rtrim($outputPath, DIRECTORY_SEPARATOR);
    }

    public function copyAndObfuscate($directoriesToObfuscate, $filesToObfuscate) {
        // Create the base output directory if it doesn't exist
        if (!is_dir($this->outputPath)) {
            mkdir($this->outputPath, 0755, true);
        }

        // Copy all files and directories to the output path
        $this->copyDirectory($this->inputPath, $this->outputPath);

        // Obfuscate specified directories
        foreach ($directoriesToObfuscate as $directory) {
            $this->obfuscateDirectory($directory);
        }

        // Obfuscate specified files
        foreach ($filesToObfuscate as $file) {
            $relativePath = str_replace($this->inputPath, '', $file);
            $outputFilePath = $this->outputPath . DIRECTORY_SEPARATOR . ltrim($relativePath, DIRECTORY_SEPARATOR);
            $this->obfuscateFile($file, $outputFilePath);
        }
    }

    private function copyDirectory($src, $dst) {
        $dir = opendir($src);
        if (!is_dir($dst)) {
            mkdir($dst, 0755, true);
        }

        while (false !== ($file = readdir($dir))) {
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

    public function obfuscateFile($filePath, $outputFilePath) {
        $data = "if (ob_get_length()) { ob_end_clean(); } ?>";
        $data .= php_strip_whitespace($filePath);

        // Compress the data
        $compressedData = gzcompress($data, 9);

        // Encode in base64
        $encodedData = base64_encode($compressedData);

        $out = <<<PHP
<?php
ob_start();
\$data = '$encodedData';
eval(gzuncompress(base64_decode(\$data)));
\$output = ob_get_contents();
ob_end_clean();
echo \$output;
?>
PHP;

        // Create the output directory if it doesn't exist
        $outputDir = dirname($outputFilePath);
        if (!is_dir($outputDir)) {
            mkdir($outputDir, 0755, true);
        }

        // Write the obfuscated code to the output file
        if (file_put_contents($outputFilePath, $out) === false) {
            throw new Exception("Error: Failed to write to the output file $outputFilePath.");
        }
    }

    public function obfuscateDirectory($directory) {
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory));
        foreach ($files as $file) {
            if ($file->isDir()) continue;
            if ($file->getExtension() !== 'php') continue;

            $relativePath = str_replace($this->inputPath, '', $file->getRealPath());
            $outputFilePath = $this->outputPath . DIRECTORY_SEPARATOR . ltrim($relativePath, DIRECTORY_SEPARATOR);

            // Only obfuscate the file if it's in a directory to be obfuscated
            $this->obfuscateFile($file->getRealPath(), $outputFilePath);
        }
    }
}
