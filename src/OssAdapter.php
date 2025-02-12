<?php

/*
 * This file is part of the iidestiny/flysystem-oss.
 *
 * (c) iidestiny <iidestiny@vip.qq.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Iidestiny\Flysystem\Oss;

use Iidestiny\Flysystem\Oss\Traits\SignatureTrait;
use League\Flysystem\AdapterInterface;
use League\Flysystem\Adapter\AbstractAdapter;
use League\Flysystem\Adapter\Polyfill\NotSupportingVisibilityTrait;
use League\Flysystem\Config;
use OSS\Core\OssException;
use OSS\Credentials\StaticCredentialsProvider;
use OSS\OssClient;

/**
 * Class OssAdapter.
 *
 * @author iidestiny <iidestiny@vip.qq.com>
 */
class OssAdapter extends AbstractAdapter
{
    use NotSupportingVisibilityTrait;
    use SignatureTrait;

    /**
     * 系统参数
     */
    public const SYSTEM_FIELD = [
        'bucket' => '${bucket}',
        'etag' => '${etag}',
        'filename' => '${object}',
        'size' => '${size}',
        'mimeType' => '${mimeType}',
        'height' => '${imageInfo.height}',
        'width' => '${imageInfo.width}',
        'format' => '${imageInfo.format}',
    ];

    protected $accessKeyId;

    protected $accessKeySecret;

    protected $endpoint;

    protected string $bucketName = '';

    protected bool $isCName = false;

    /**
     * @var array<string, array>
     */
    protected array $buckets = [];

    /**
     * @var array<string, OssAdapter>
     */
    protected array $bucketAdapters = [];

    /**
     * @var OssClient
     */
    protected $client;

    /**
     * @var array
     */
    protected array $params = [];

    /**
     * @var bool
     */
    protected bool $useSSL = false;

    /**
     * @var string|null
     */
    protected ?string $cdnUrl = null;

    /**
     * OssAdapter constructor.
     *
     * @param       $accessKeyId
     * @param       $accessKeySecret
     * @param       $endpoint
     * @param       $bucket
     * @param bool $isCName
     * @param string $prefix
     * @param array $buckets
     * @param mixed ...$params
     */
    public function __construct($accessKeyId, $accessKeySecret, $endpoint, $bucket, bool $isCName = false, string $prefix = '', array $buckets = [], array $params = [])
    {
        $this->accessKeyId = $accessKeyId;
        $this->accessKeySecret = $accessKeySecret;
        $this->endpoint = $endpoint;
        $this->bucketName = $bucket;
        $this->isCName = $isCName;
        $this->setPathPrefix($prefix);
        $this->buckets = $buckets;
        $this->params = $params;
        $this->initDefaultBucketAdapter();
    }

    public function getBucketName(): string
    {
        return $this->bucketName;
    }

    /**
     * init default bucket adapter.
     *
     * @return $this
     */
    protected function initDefaultBucketAdapter(): OssAdapter
    {
        $this->initClient()
            ->checkEndpoint()
            ->bucketAdapters[$this->bucketName] = $this;

        return $this;
    }

    /**
     * set cdn url.
     *
     * @param string|null $url
     * @return $this
     */
    public function setCdnUrl(?string $url): OssAdapter
    {
        $this->cdnUrl = $url;

        return $this;
    }

    /**
     * get bucket adapter by bucket name.
     *
     * @return $this
     * @throws \InvalidArgumentException
     */
    public function bucket($bucket): OssAdapter
    {
        return $this->bucketAdapters[$bucket] ?? ($this->bucketAdapters[$bucket] = $this->createBucketAdapter($bucket));
    }

    /**
     * create bucket adapter by bucket name.
     *
     * @param string $bucket
     * @return \Iidestiny\Flysystem\Oss\OssAdapter
     * @throws \InvalidArgumentException
     */
    protected function createBucketAdapter(string $bucket): OssAdapter
    {
        if (!isset($this->buckets[$bucket])) {
            throw new \InvalidArgumentException(sprintf('Bucket "%s" does not exist.', $bucket));
        }

        $config = $this->buckets[$bucket];
        $extra = array_merge($this->params, $this->extraConfig($config));

        // new bucket adapter
        $adapter = new self(
            $config['access_key'] ?? $this->accessKeyId,
            $config['secret_key'] ?? $this->accessKeySecret,
            $config['endpoint'] ?? $this->endpoint,
            $config['bucket'],
            $config['isCName'] ?? false,
            $config['root'] ?? '',
            [],
            $extra);

        return $adapter->setCdnUrl($config['url'] ?? null)->initDefaultBucketAdapter();
    }

    /**
     * extract extra config.
     *
     * @param array $config
     * @return array
     */
    protected function extraConfig(array $config): array
    {
        return array_diff_key($config, array_flip(['driver', 'root', 'buckets', 'access_key', 'secret_key',
            'endpoint', 'bucket', 'isCName', 'url']));
    }

    /**
     * init oss client.
     *
     * @return $this
     */
    protected function initClient(): OssAdapter
    {
        $provider = new StaticCredentialsProvider($this->accessKeyId, $this->accessKeySecret, $this->params['securityToken'] ?? null);

        $this->client = new OssClient(array_merge([
            'endpoint' => rtrim($this->endpoint, '/'),
            'cname'    => $this->isCName,
            'provider' => $provider,
        ], $this->params));

        return $this;
    }

    /**
     * get ali sdk kernel class.
     */
    public function getClient(): OssClient
    {
        return $this->client;
    }

    /**
     * 验签.
     */
    public function verify(): array
    {
        // oss 前面 header、公钥 header
        $authorizationBase64 = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        $pubKeyUrlBase64 = $_SERVER['HTTP_X_OSS_PUB_KEY_URL'] ?? '';
        // 验证失败
        if (empty($authorizationBase64) || empty($pubKeyUrlBase64)) {
            return [false, ['CallbackFailed' => 'authorization or pubKeyUrl is null']];
        }

        // 获取OSS的签名
        $authorization = base64_decode($authorizationBase64);
        // 获取公钥
        $pubKeyUrl = base64_decode($pubKeyUrlBase64);
        // 请求验证
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $pubKeyUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        if (!$pubKey = curl_exec($ch)) {
            return [false, ['CallbackFailed' => 'curl is fail']];
        }

        // 获取回调 body
        $body = file_get_contents('php://input');
        // 拼接待签名字符串
        $path = $_SERVER['REQUEST_URI'];
        $pos = strpos($path, '?');
        if (false === $pos) {
            $authStr = urldecode($path)."\n".$body;
        } else {
            $authStr = urldecode(substr($path, 0, $pos)).substr($path, $pos, strlen($path) - $pos)."\n".$body;
        }
        // 验证签名
        $ok = openssl_verify($authStr, $authorization, $pubKey, OPENSSL_ALGO_MD5);

        if (1 !== $ok) {
            curl_close($ch);

            return [false, ['CallbackFailed' => 'verify is fail, Illegal data']];
        }

        parse_str($body, $data);
        curl_close($ch);

        return [true, $data];
    }

    /**
     * oss 直传配置.
     *
     * @param string $prefix 目录前缀
     * @param null $callBackUrl 回调地址
     * @param array $customData 自定义参数
     * @param int $expire 过期时间（秒）
     * @param array $systemData 系统接收参数，回调时会返回
     * @param array $policyData 自定义 policy 参数
     *                          see: https://help.aliyun.com/zh/oss/developer-reference/postobject#section-d5z-1ww-wdb
     * @return string
     * @throws \JsonException|\InvalidArgumentException|\DateMalformedStringException
     * @see https://help.aliyun.com/zh/oss/use-cases/overview-20
     */
    public function signatureConfig(string $prefix = '', $callBackUrl = null, array $customData = [], int $expire = 30, array $systemData = [], array $policyData = []): string
    {
        $prefix = $this->applyPathPrefix($prefix);

        // 系统参数
        $system = [];
        if (empty($systemData)) {
            $system = self::SYSTEM_FIELD;
        } else {
            foreach ($systemData as $key => $value) {
                if (!in_array($value, self::SYSTEM_FIELD, true)) {
                    throw new \InvalidArgumentException("Invalid oss system filed: {$value}");
                }
                $system[$key] = $value;
            }
        }

        // 自定义参数
        $callbackVar = [];
        $data = [];
        if (!empty($customData)) {
            foreach ($customData as $key => $value) {
                $callbackVar['x:'.$key] = $value;
                $data[$key] = '${x:'.$key.'}';
            }
        }

        $callbackParam = [
            'callbackUrl' => $callBackUrl,
            'callbackBody' => urldecode(http_build_query(array_merge($system, $data))),
            'callbackBodyType' => 'application/x-www-form-urlencoded',
        ];
        $callbackString = json_encode($callbackParam, JSON_THROW_ON_ERROR);
        $base64CallbackBody = base64_encode($callbackString);

        $now = time();
        $end = $now + $expire;
        $expiration = $this->gmt_iso8601($end);

        // 如果用户没有设置文件大小，需要设置默认值
        $hasContentLengthRange = false;
        $contentLengthRangeKey = 'content-length-range';
        foreach ($policyData as $item) {
            if (isset($item[0]) && $item[0] === $contentLengthRangeKey) {
                $hasContentLengthRange = true;
                break;
            }
        }
        if (!$hasContentLengthRange) {
            $condition = [
                0 => $contentLengthRangeKey,
                1 => 0, // min: 0
                2 => 1048576000, // max: 1GB
            ];
            $conditions[] = $condition;
        }
        $conditions[] = [
            0 => 'starts-with',
            1 => '$key',
            2 => $prefix,
        ];

        $arr = [
            'expiration' => $expiration,
            'conditions' => array_merge($conditions, $policyData), // 将自定义policy参数一起合并
        ];
        $policy = json_encode($arr, JSON_THROW_ON_ERROR);
        $base64Policy = base64_encode($policy);
        $stringToSign = $base64Policy;
        $signature = base64_encode(hash_hmac('sha1', $stringToSign, $this->accessKeySecret, true));

        $response = [];
        $response['accessid'] = $this->accessKeyId;
        $response['host'] = $this->normalizeHost();
        $response['policy'] = $base64Policy;
        $response['signature'] = $signature;
        $response['expire'] = $end;
        $response['callback'] = $base64CallbackBody;
        $response['callback-var'] = $callbackVar;
        $response['dir'] = $prefix;  // 这个参数是设置用户上传文件时指定的前缀。

        return json_encode($response, JSON_THROW_ON_ERROR);
    }

    /**
     * sign url.
     *
     * @param string $path
     * @param int $timeout
     * @param array $options
     * @param string $method
     * @return string
     * @throws \OSS\Core\OssException
     * @see self::getTemporaryUrl
     */
    public function signUrl(string $path, int $timeout, array $options = [], $method = OssClient::OSS_HTTP_GET): string
    {
        return $this->getTemporaryUrl($path, $timeout, $options, $method);
    }

    /**
     * sign url.
     *
     * @param string $path
     * @param int $timeout
     * @param array $options
     * @param string $method
     * @return false|string
     * @throws \OSS\Core\OssException
     */
    public function getTemporaryUrl(string $path, int $timeout, array $options = [], string $method = OssClient::OSS_HTTP_GET): string
    {
        $path = $this->applyPathPrefix($path);

        return $this->client->signUrl($this->bucketName, $path, $timeout, $method, $options);
    }

    /**
     * write a file.
     *
     * @param string $path
     * @param string $contents
     *
     * @return bool
     */
    public function write($path, $contents, Config $config)
    {
        $path = $this->applyPathPrefix($path);
        $options = $config->get('options', []);

        $this->client->putObject($this->bucketName, $path, $contents, $options);

        return true;
    }

    /**
     * Write a new file using a stream.
     *
     * @param string $path
     * @param resource $resource
     * @param \League\Flysystem\Config $config
     * @return bool
     * @throws \OSS\Core\OssException
     * @throws \OSS\Http\RequestCore_Exception
     */
    public function writeStream($path, $resource, Config $config)
    {
        $path = $this->applyPathPrefix($path);
        $options = $config->get('options', []);

        $this->client->uploadStream($this->bucketName, $path, $resource, $options);
        return true;
    }

    /**
     * Update a file.
     *
     * @param string $path
     * @param string $contents
     *
     * @return bool
     */
    public function update($path, $contents, Config $config)
    {
        return $this->write($path, $contents, $config);
    }

    /**
     * Update a file using a stream.
     *
     * @param string   $path
     * @param resource $resource
     *
     * @return bool
     */
    public function updateStream($path, $resource, Config $config)
    {
        return $this->writeStream($path, $resource, $config);
    }

    /**
     * rename a file.
     *
     * @param string $path
     * @param string $newpath
     *
     * @return bool
     *
     * @throws OssException
     */
    public function rename($path, $newpath)
    {
        if (!$this->copy($path, $newpath)) {
            return false;
        }

        return $this->delete($path);
    }

    /**
     * copy a file.
     *
     * @param string $path
     * @param string $newpath
     *
     * @return bool
     */
    public function copy($path, $newpath)
    {
        $path = $this->applyPathPrefix($path);
        $newpath = $this->applyPathPrefix($newpath);

        $this->client->copyObject($this->bucketName, $path, $this->bucketName, $newpath);
        return true;
    }

    /**
     * delete a file.
     *
     * @param string $path
     *
     * @return bool
     *
     * @throws OssException
     */
    public function delete($path)
    {
        $path = $this->applyPathPrefix($path);

        $this->client->deleteObject($this->bucketName, $path);
        return true;
    }

    /**
     * Delete a directory.
     *
     * @param string $dirname
     *
     * @return bool
     *
     * @throws OssException
     */
    public function deleteDir($dirname)
    {
        $fileList = $this->listContents($dirname, true);
        foreach ($fileList as $file) {
            $this->delete($file['path']);
        }

        return !$this->has($dirname);
    }

    /**
     * create a directory.
     *
     * @param string $dirname
     *
     * @return bool
     */
    public function createDir($dirname, Config $config)
    {
        $this->client->createObjectDir($this->bucketName, $this->applyPathPrefix($dirname));

        return true;
    }

    /**
     * visibility.
     *
     * @param string $path
     * @param string $visibility
     *
     * @return array|bool|false
     */
    public function setVisibility($path, $visibility)
    {
        $object = $this->applyPathPrefix($path);
        $acl = AdapterInterface::VISIBILITY_PUBLIC === $visibility ? OssClient::OSS_ACL_TYPE_PUBLIC_READ : OssClient::OSS_ACL_TYPE_PRIVATE;

        try {
            $this->client->putObjectAcl($this->bucketName, $object, $acl);
        } catch (OssException $exception) {
            return false;
        }

        return compact('visibility');
    }

    /**
     * Check whether a file exists.
     *
     * @param string $path
     *
     * @return array|bool|null
     */
    public function has($path)
    {
        $path = $this->applyPathPrefix($path);

        return $this->client->doesObjectExist($this->bucketName, $path);
    }

    /**
     * Get resource url.
     *
     * @param string $path
     *
     * @return string
     */
    public function getUrl(string $path)
    {
        $path = $this->applyPathPrefix($path);

        if (!is_null($this->cdnUrl)) {
            return rtrim($this->cdnUrl, '/').'/'.ltrim($path, '/');
        }

        return $this->normalizeHost().ltrim($path, '/');
    }

    /**
     * read a file.
     *
     * @param string $path
     *
     * @return array|bool|false
     */
    public function read($path)
    {
        try {
            $contents = $this->getObject($path);
        } catch (OssException $exception) {
            return false;
        }

        return compact('contents', 'path');
    }

    /**
     * read a file stream.
     *
     * @param string $path
     *
     * @return array|bool|false
     */
    public function readStream($path)
    {
        try {
            $stream = fopen('php://temp', 'w+b');
            fwrite($stream, $this->getObject($path));
            rewind($stream);
        } catch (OssException $exception) {
            return false;
        }

        return compact('stream', 'path');
    }

    /**
     * Lists all files in the directory.
     *
     * @param string $directory
     * @param bool   $recursive
     *
     * @return array
     *
     * @throws OssException
     */
    public function listContents($directory = '', $recursive = false)
    {
        $list = [];
        $directory = '/' == substr($directory, -1) ? $directory : $directory.'/';
        $result = $this->listDirObjects($directory, $recursive);

        if (!empty($result['objects'])) {
            foreach ($result['objects'] as $files) {
                if (!$fileInfo = $this->normalizeFileInfo($files)) {
                    continue;
                }
                $list[] = $fileInfo;
            }
        }

        // prefix
        if (!empty($result['prefix'])) {
            foreach ($result['prefix'] as $dir) {
                $list[] = [
                    'type' => 'dir',
                    'path' => $dir,
                ];
            }
        }

        return $list;
    }

    /**
     * get meta data.
     *
     * @param string $path
     *
     * @return array|bool|false
     */
    public function getMetadata($path)
    {
        $path = $this->applyPathPrefix($path);

        try {
            $metadata = $this->client->getObjectMeta($this->bucketName, $path);
        } catch (OssException $exception) {
            return false;
        }

        return $metadata;
    }

    /**
     * get the size of file.
     *
     * @param string $path
     *
     * @return array|false
     */
    public function getSize($path)
    {
        return $this->normalizeFileInfo(['Key' => $path]);
    }

    /**
     * get mime type.
     *
     * @param string $path
     *
     * @return array|false
     */
    public function getMimetype($path)
    {
        return $this->normalizeFileInfo(['Key' => $path]);
    }

    /**
     * get timestamp.
     *
     * @param string $path
     *
     * @return array
     */
    public function getTimestamp($path)
    {
        return $this->normalizeFileInfo(['Key' => $path]);
    }

    /**
     * normalize Host.
     *
     * @return string
     */
    protected function normalizeHost(): string
    {
        if ($this->isCName) {
            $domain = $this->endpoint;
        } else {
            $domain = $this->bucketName.'.'.$this->endpoint;
        }

        if ($this->useSSL) {
            $scheme = 'https';
        } else {
            $scheme = 'http';
        }

        return rtrim($scheme.'://'.$domain, '/').'/';
    }

    /**
     * Check the endpoint to see if SSL can be used.
     */
    protected function checkEndpoint(): OssAdapter
    {
        if (str_starts_with($this->endpoint, 'http://')) {
            $this->endpoint = substr($this->endpoint, strlen('http://'));
            $this->useSSL = false;
        } elseif (str_starts_with($this->endpoint, 'https://')) {
            $this->endpoint = substr($this->endpoint, strlen('https://'));
            $this->useSSL = true;
        }

        return $this;
    }

    /**
     * Read an object from the OssClient.
     *
     * @param string $path
     *
     * @return string
     * @throws \OSS\Core\OssException
     * @throws \OSS\Http\RequestCore_Exception
     */
    protected function getObject(string $path)
    {
        $path = $this->applyPathPrefix($path);

        return $this->client->getObject($this->bucketName, $path);
    }

    /**
     * File list core method.
     *
     * @param string $dirname
     * @param bool   $recursive
     *
     * @return array
     *
     * @throws OssException
     */
    public function listDirObjects($dirname = '', $recursive = false)
    {
        $delimiter = '/';
        $nextMarker = '';
        $maxkeys = 1000;

        $result = [];

        while (true) {
            $options = [
                'delimiter' => $delimiter,
                'prefix' => $dirname,
                'max-keys' => $maxkeys,
                'marker' => $nextMarker,
            ];

            try {
                $listObjectInfo = $this->client->listObjects($this->bucketName, $options);
            } catch (OssException $exception) {
                throw $exception;
            }

            $nextMarker = $listObjectInfo->getNextMarker();
            $objectList = $listObjectInfo->getObjectList();
            $prefixList = $listObjectInfo->getPrefixList();

            if (!empty($objectList)) {
                foreach ($objectList as $objectInfo) {
                    $object['Prefix'] = $dirname;
                    $object['Key'] = $objectInfo->getKey();
                    $object['LastModified'] = $objectInfo->getLastModified();
                    $object['eTag'] = $objectInfo->getETag();
                    $object['Type'] = $objectInfo->getType();
                    $object['Size'] = $objectInfo->getSize();
                    $object['StorageClass'] = $objectInfo->getStorageClass();
                    $result['objects'][] = $object;
                }
            } else {
                $result['objects'] = [];
            }

            if (!empty($prefixList)) {
                foreach ($prefixList as $prefixInfo) {
                    $result['prefix'][] = $prefixInfo->getPrefix();
                }
            } else {
                $result['prefix'] = [];
            }

            // Recursive directory
            if ($recursive) {
                foreach ($result['prefix'] as $prefix) {
                    $next = $this->listDirObjects($prefix, $recursive);
                    $result['objects'] = array_merge($result['objects'], $next['objects']);
                }
            }

            if ('' === $nextMarker) {
                break;
            }
        }

        return $result;
    }

    /**
     * normalize file info.
     *
     * @param array $stats
     * @return array
     */
    protected function normalizeFileInfo(array $stats): array
    {
        $filePath = ltrim($stats['Key'], '/');

        $meta = $this->getMetadata($filePath) ?? [];

        if (empty($meta)) {
            return [];
        }

        return [
            'type' => 'file',
            'mimetype' => $meta['content-type'],
            'path' => $filePath,
            'timestamp' => $meta['info']['filetime'],
            'size' => $meta['content-length'],
        ];
    }
}
