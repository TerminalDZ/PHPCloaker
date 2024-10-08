# PHPCloaker

PHPCloaker is a robust PHP code obfuscation tool designed to protect your source code from unauthorized access and reverse engineering. It offers a simple yet powerful way to obfuscate PHP files and directories, making it significantly harder for potential attackers to understand or modify your code.

## Features

- Obfuscate individual PHP files or entire directories
- Preserve directory structure in the obfuscated output
- Compress and encode obfuscated code for extra security
- Easy-to-use interface for specifying input and output paths

## How It Works

PHPCloaker uses a multi-step process to obfuscate your PHP code:

1. **File Preparation**: The tool first strips whitespace and comments from the PHP files to reduce size and remove potentially revealing information.

2. **Encryption**: The prepared code is compressed, base64 encoded, and then encrypted using AES-256-CBC encryption with a unique secret key for each file.

3. **Key Management**: The secret keys are stored separately in a protected directory, with their file paths also encrypted.

4. **Obfuscated Output**: The tool generates new PHP files that contain the encrypted code along with a decryption mechanism. When executed, these files will decrypt and run the original code.

5. **Directory Structure Preservation**: If obfuscating a directory, PHPCloaker maintains the original directory structure in the output.

## Installation

1. Clone this repository:

   ```
   git clone https://github.com/TerminalDZ/PHPCloaker.git
   ```

2. Navigate to the project directory:
   ```
   cd PHPCloaker
   ```

## Usage

1. Edit the `index.php` file to specify your input and output paths:

```php
$sourceDir = 'public_html';
$destinationDir = 'obfuscated_html';
$keyDirectory = 'keys_storage';

$dirsToObfuscate = [
    "$sourceDir/app",
    // Add more directories as needed
];

$filesToObfuscate = [
    "$sourceDir/index.php",
    // Add more files as needed
];
```

2. Run the script:

```
php index.php
```

3. Your obfuscated files will be generated in the specified output directory.

## Obfuscation Process

1. **File Processing**: PHPCloaker iterates through the specified files and directories.

2. **Content Preparation**: For each PHP file, it removes whitespace and comments, then prepends code to clear any existing output buffers.

3. **Encryption**: The prepared content is compressed, base64 encoded, and then encrypted using a randomly generated secret key.

4. **Key Storage**: The secret key for each file is stored in a separate, protected directory. The path to this key file is also encrypted.

5. **Obfuscated File Generation**: A new PHP file is created containing:

   - The encrypted content
   - The encrypted path to the key file
   - A decryption routine that will retrieve the key, decrypt the content, and execute it when the file is run

6. **Directory Structure**: If obfuscating directories, the original structure is maintained in the output.

## Important Notes

- Always keep a backup of your original files before obfuscation.
- Obfuscation is not foolproof. While it significantly increases the difficulty of reverse engineering, it does not guarantee absolute security.
- Ensure you have the necessary permissions to read from the input directory and write to the output directory.
- The security of your obfuscated code depends on keeping the key directory secure. Anyone with access to both the obfuscated files and the key directory can potentially decrypt your code.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
