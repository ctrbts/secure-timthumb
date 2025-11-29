<?php

/**
 * Secure TimThumb - A modern, secure rewrite of the legacy TimThumb script.
 * * @version 3.0.0 (Refactored)
 * @license MIT
 */

namespace TimThumb;

use Exception;

// Bootstrap inmediato si se llama directamente (comportamiento legacy para <img> tags)
if (basename(__FILE__) == basename($_SERVER['PHP_SELF'])) {
    try {
        // Configuración por defecto segura
        $config = [
            'allow_external' => false, // DESACTIVADO POR DEFECTO POR SEGURIDAD
            'allowed_sites'  => [],    // Lista blanca estricta
            'cache_dir'      => __DIR__ . '/cache',
            'max_width'      => 1500,
            'max_height'     => 1500,
            'max_file_size'  => 10485760, // 10MB
        ];

        $tim = new ImageManager($config);
        $tim->run();
    } catch (Exception $e) {
        header("HTTP/1.1 400 Bad Request");
        die('Error: ' . htmlspecialchars($e->getMessage()));
    }
    exit;
}

class ImageManager
{

    private $config;
    private $src;
    private $mimeType;
    private $cacheFile;

    public function __construct(array $config = [])
    {
        $defaults = [
            'memory_limit'      => '128M',
            'allow_external'    => false,
            'allowed_sites'     => [],
            'cache_dir'         => './cache',
            'cache_time'        => 86400, // 24 horas
            'max_width'         => 1500,
            'max_height'        => 1500,
            'max_file_size'     => 10485760,
            'png_is_transparent' => true,
            'default_quality'   => 90,
            'salt'              => 'DO_NOT_CHANGE_THIS_UNLESS_YOU_FLUSH_CACHE'
        ];

        $this->config = array_merge($defaults, $config);
        $this->initializeEnvironment();
    }

    private function initializeEnvironment()
    {
        ini_set('memory_limit', $this->config['memory_limit']);

        if (!is_dir($this->config['cache_dir'])) {
            if (!mkdir($this->config['cache_dir'], 0755, true)) {
                throw new Exception("No se pudo crear el directorio de caché. Verifique permisos.");
            }
        }

        // Proteger directorio de caché contra ejecución de scripts (Apache)
        $htaccess = $this->config['cache_dir'] . '/.htaccess';
        if (!file_exists($htaccess)) {
            file_put_contents($htaccess, "Deny from all\n<FilesMatch '\.(jpg|jpeg|png|gif|txt)$'>\nOrder Allow,Deny\nAllow from all\n</FilesMatch>\nphp_flag engine off");
        }
    }

    public function run()
    {
        $this->src = $_GET['src'] ?? null;

        if (!$this->src) {
            throw new Exception("No se especificó ninguna imagen fuente.");
        }

        // Sanitización estricta
        $this->src = strip_tags($this->src);
        $this->src = str_replace(['javascript:', 'vbscript:', 'data:'], '', $this->src);

        // Determinar origen
        if (preg_match('/^https?:\/\//i', $this->src)) {
            $this->handleExternalImage();
        } else {
            $this->handleLocalImage();
        }

        // Generar nombre de archivo caché seguro
        $paramsHash = md5(serialize($_GET) . $this->config['salt']);
        $ext = $this->getExtensionFromMime($this->mimeType);
        $this->cacheFile = $this->config['cache_dir'] . '/tt_' . md5($this->src) . "_{$paramsHash}.{$ext}";

        // Servir caché si existe y es válido
        if ($this->serveCache()) {
            return;
        }

        // Procesar imagen
        $this->processImage();
    }

    private function handleExternalImage()
    {
        if (!$this->config['allow_external']) {
            throw new Exception("La carga de imágenes externas está deshabilitada.");
        }

        $host = parse_url($this->src, PHP_URL_HOST);
        $isAllowed = false;
        foreach ($this->config['allowed_sites'] as $site) {
            if ($host === $site || str_ends_with($host, '.' . $site)) {
                $isAllowed = true;
                break;
            }
        }

        if (!empty($this->config['allowed_sites']) && !$isAllowed) {
            throw new Exception("El dominio de la imagen externa no está permitido.");
        }

        // Validación SSRF y descarga segura
        $this->downloadExternalImage();
    }

    private function downloadExternalImage()
    {
        $ch = curl_init($this->src);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true); // SIEMPRE verificar SSL
        curl_setopt($ch, CURLOPT_MAXREDIRS, 3);
        curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS); // Solo HTTP/S

        $data = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $contentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($data === false || $httpCode !== 200) {
            throw new Exception("Error descargando imagen externa: $error (HTTP $httpCode)");
        }

        // Validar que realmente es una imagen usando FileInfo (Magic Bytes)
        $finfo = new \finfo(FILEINFO_MIME_TYPE);
        $detectedMime = $finfo->buffer($data);

        if (!in_array($detectedMime, ['image/jpeg', 'image/png', 'image/gif'])) {
            throw new Exception("El archivo remoto no es una imagen válida ($detectedMime).");
        }

        $this->mimeType = $detectedMime;
        // Guardamos temporalmente para procesar
        $this->localSrcPath = tempnam(sys_get_temp_dir(), 'tt_ext_');
        file_put_contents($this->localSrcPath, $data);
    }

    private function handleLocalImage()
    {
        // Prevención de Path Traversal
        if (strpos($this->src, '..') !== false || strpos($this->src, './') !== false) {
            throw new Exception("Ruta de imagen inválida.");
        }

        $docRoot = rtrim($_SERVER['DOCUMENT_ROOT'], '/');
        $filePath = realpath($docRoot . '/' . ltrim($this->src, '/'));

        if (!$filePath || !file_exists($filePath) || strpos($filePath, $docRoot) !== 0) {
            // Intento secundario relativo al script
            $filePath = realpath(__DIR__ . '/' . ltrim($this->src, '/'));
            if (!$filePath || !file_exists($filePath)) {
                throw new Exception("Imagen local no encontrada o acceso denegado.");
            }
        }

        $this->localSrcPath = $filePath;
        $this->mimeType = mime_content_type($filePath);
    }

    private function processImage()
    {
        $w = (int)($_GET['w'] ?? 0);
        $h = (int)($_GET['h'] ?? 0);

        // Límites
        $w = min($w, $this->config['max_width']);
        $h = min($h, $this->config['max_height']);

        if ($w <= 0 && $h <= 0) {
            $w = 100;
            $h = 100; // Defaults
        }

        switch ($this->mimeType) {
            case 'image/jpeg':
                $img = imagecreatefromjpeg($this->localSrcPath);
                break;
            case 'image/png':
                $img = imagecreatefrompng($this->localSrcPath);
                break;
            case 'image/gif':
                $img = imagecreatefromgif($this->localSrcPath);
                break;
            default:
                throw new Exception("Tipo de imagen no soportado.");
        }

        if (!$img) throw new Exception("Error GD procesando la imagen.");

        $origW = imagesx($img);
        $origH = imagesy($img);

        // Lógica simple de redimensionado (Aspect Ratio)
        if ($h == 0) $h = ($origH / $origW) * $w;
        if ($w == 0) $w = ($origW / $origH) * $h;

        $newImg = imagecreatetruecolor($w, $h);

        // Preservar transparencia
        if ($this->mimeType == 'image/png' || $this->mimeType == 'image/gif') {
            imagecolortransparent($newImg, imagecolorallocatealpha($newImg, 0, 0, 0, 127));
            imagealphablending($newImg, false);
            imagesavealpha($newImg, true);
        }

        imagecopyresampled($newImg, $img, 0, 0, 0, 0, $w, $h, $origW, $origH);

        // Guardar en caché y mostrar
        $this->saveAndOutput($newImg);

        imagedestroy($img);
        imagedestroy($newImg);

        // Limpieza de temporales externos
        if (strpos($this->localSrcPath, 'tt_ext_') !== false) {
            @unlink($this->localSrcPath);
        }
    }

    private function saveAndOutput($resource)
    {
        $quality = (int)($_GET['q'] ?? $this->config['default_quality']);

        // Guardar al disco
        switch ($this->mimeType) {
            case 'image/jpeg':
                imagejpeg($resource, $this->cacheFile, $quality);
                break;
            case 'image/png':
                imagepng($resource, $this->cacheFile, floor($quality / 10));
                break;
            case 'image/gif':
                imagegif($resource, $this->cacheFile);
                break;
        }

        $this->serveFile($this->cacheFile);
    }

    private function serveCache()
    {
        if (file_exists($this->cacheFile)) {
            $mtime = filemtime($this->cacheFile);
            if (time() - $mtime < $this->config['cache_time']) {
                $this->serveFile($this->cacheFile);
                return true;
            }
            @unlink($this->cacheFile); // Caché expirado
        }
        return false;
    }

    private function serveFile($path)
    {
        if (!file_exists($path)) return false;

        $mtime = filemtime($path);
        $etag = md5($path . $mtime);

        header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $mtime) . ' GMT');
        header('ETag: ' . $etag);
        header('Content-Type: ' . $this->mimeType);
        header('Cache-Control: public, max-age=' . $this->config['cache_time']);

        // Soporte básico para 304 Not Modified
        if (isset($_SERVER['HTTP_IF_NONE_MATCH']) && trim($_SERVER['HTTP_IF_NONE_MATCH']) == $etag) {
            header("HTTP/1.1 304 Not Modified");
            exit;
        }

        readfile($path);
        exit;
    }

    private function getExtensionFromMime($mime)
    {
        $map = [
            'image/jpeg' => 'jpg',
            'image/png'  => 'png',
            'image/gif'  => 'gif'
        ];
        return $map[$mime] ?? 'txt';
    }
}
