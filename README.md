# Secure TimThumb (Modern Refactor)

A secure, modern rewrite of the `timthumb.php` script. This project aims to provide a drop-in replacement for legacy systems that still rely on TimThumb, mitigating the critical RCE and file inclusion vulnerabilities present in the original version.

⚠️ WARNING: This library is intended for legacy maintenance. For new projects, maybe you prefer a modern solutions like Intervention Image or cloud-based services.

## Key Security Improvements

- Strict MIME Type Checking: Uses finfo to validate magic bytes. Malicious files renamed to `.jpg` will be rejected.
- No Webshots: The vulnerable `exec()` based website screenshot feature has been removed entirely.
- External Sites Disabled by Default: Must be explicitly enabled via config.
- SSRF Protection: cURL is restricted to HTTP/HTTPS protocols only to prevent internal network scanning.
- Cache Execution Prevention: Automatically generates an `.htaccess` in the cache directory to prevent PHP execution.

## Installation

### Option A: 
    
Composer (Recommended)

```bash
composer require ctrbts/secure-timthumb
```

### Option B: 

Drop-in Replacement (Manual)

1. Download `TimThumb.php` from this repository.
2. Replace your existing `timthumb.php` file.
3. Ensure the *cache* directory exists and is writable by the web server.

## Configuration

You can configure the script by instantiating the class with an array of options (if using as a library) or by editing the default config array at the top of the TimThumb.php file (if using as a standalone script).

```php
// Example Configuration
$config = [
    'allow_external' => true,
    'allowed_sites'  => ['flickr.com', 'staticflickr.com'],
    'max_file_size'  => 5242880, // 5MB
];
```
## Attribution & Transparency

Maintainer: [Fernando Merlo](https://github.com/ctrbts)
Original Authors: [Ben Gillbanks](https://github.com/bengillbanks) & [Mark Maunder](https://github.com/markmaunder)

**Refactor Note:** This codebase was refactored with the assistance of AI tools to analyze historical security flaws and implement modern PHP security standards (PSR, Strict Types, Exception Handling).

**Disclaimer:** This software is provided "as is", without warranty of any kind. Use at your own risk.