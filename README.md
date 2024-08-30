# PHPCloaker

PHPCloaker is a robust PHP code obfuscation tool designed to protect your source code from unauthorized access and reverse engineering. It offers a simple yet powerful way to obfuscate PHP files and directories, making it significantly harder for potential attackers to understand or modify your code.

## Features

- Obfuscate individual PHP files or entire directories
- Preserve directory structure in the obfuscated output
- Compress and encode obfuscated code for extra security
- Easy-to-use interface for specifying input and output paths

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
$inputBasePath = 'path/to/your/input/directory';
$outputBasePath = 'path/to/your/output/directory';

$directoriesToObfuscate = [
    "$inputBasePath/app",
    // Add more directories as needed
];

$filesToObfuscate = [
    "$inputBasePath/index.php",
    // Add more files as needed
];
```

2. Run the script:

```
php index.php
```

3. Your obfuscated files will be generated in the specified output directory.

## Important Notes

- Always keep a backup of your original files before obfuscation.
- Obfuscation is not foolproof. While it significantly increases the difficulty of reverse engineering, it does not guarantee absolute security.
- Ensure you have the necessary permissions to read from the input directory and write to the output directory.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
