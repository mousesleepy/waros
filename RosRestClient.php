<?php
/**
 * RosRestClient — HTTP client for RouterOS 7 REST API
 *
 * Uses HTTP Basic Auth on every request (no token-based auth).
 * POST /add for address-list entries — instant, returns {"ret":"*ID"}.
 * Compatible with PHP 7.3+
 */

class RosRestClient
{
    private $baseUrl;
    private $user;
    private $password;
    private $useSsl;
    private $verifySsl;
    private $port;
    private $timeout = 65;
    private $lastError = null;
    private $lastHttpCode = 0;
    private $debug = false;

    /**
     * RouterOS rejected add because entry already exists — not an error
     */
    const ALREADY_EXISTS = 'ALREADY_EXISTS';

    public function __construct(array $config)
    {
        $this->user = $config['user'];
        $this->password = $config['password'];
        $this->useSsl = (bool)($config['use_ssl'] ?? true);
        $this->verifySsl = (bool)($config['verify_ssl'] ?? false);
        $this->port = (int)($config['port'] ?? ($this->useSsl ? 443 : 80));
        $this->baseUrl = ($this->useSsl ? 'https' : 'http') . '://' . $config['ip'] . ':' . $this->port;
        $this->debug = !empty($config['debug']);

        if ($this->debug)
        {
            fwrite(STDERR, "[RosRestClient] base={$this->baseUrl} user={$this->user} ssl="
                . ($this->useSsl ? 'yes' : 'no') . "\n");
        }
    }

    // --- Address-list operations -----------------------------------------------

    /**
     * Add entry to address-list via POST /add (instant)
     *
     * Returns:
     *   - string (.id) on success
     *   - self::ALREADY_EXISTS if IP already blocked
     *   - null on failure
     */
    public function addAddress($list, $address, $comment, $timeout = '')
    {
        $payload = [
            'list' => $list,
            'address' => $address,
            'comment' => $comment,
        ];

        if ($timeout !== '' && $timeout !== '0s')
        {
            $payload['timeout'] = $timeout;
        }

        $response = $this->request('POST', '/rest/ip/firewall/address-list/add', $payload);

        if ($response === null)
        {
            if ($this->isAlreadyExists())
            {
                return self::ALREADY_EXISTS;
            }
            return null;
        }

        if (is_array($response) && isset($response['ret']))
        {
            return $response['ret'];
        }

        return $response;
    }

    // --- HTTP layer ------------------------------------------------------------

    public function request($method, $path, array $payload = null)
    {
        $url = $this->baseUrl . $path;

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_CUSTOMREQUEST  => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => $this->timeout,
            CURLOPT_SSL_VERIFYPEER => $this->verifySsl,
            CURLOPT_SSL_VERIFYHOST => $this->verifySsl ? 2 : 0,
            CURLOPT_HEADER         => false,
            CURLOPT_USERPWD        => $this->user . ':' . $this->password,
            CURLOPT_HTTPHEADER     => [
                'Content-Type: application/json',
            ],
        ]);

        if ($payload !== null && in_array($method, ['PUT', 'PATCH', 'POST']))
        {
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
            if ($this->debug)
            {
                fwrite(STDERR, "[RosRestClient] {$method} {$url} body=" . json_encode($payload) . "\n");
            }
        }

        $body = curl_exec($ch);
        $this->lastHttpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlErrno = curl_errno($ch);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($curlErrno !== 0)
        {
            $this->lastError = 'cURL error: ' . $curlError;
            if ($this->debug)
            {
                fwrite(STDERR, "[RosRestClient] {$method} {$url} => cURL ERROR: {$this->lastError}\n");
            }
            return null;
        }

        if ($this->debug)
        {
            $bodyPreview = ($body !== false && $body !== '') ? substr($body, 0, 500) : '(empty)';
            fwrite(STDERR, "[RosRestClient] {$method} {$url} => HTTP {$this->lastHttpCode} body={$bodyPreview}\n");
        }

        if ($this->lastHttpCode >= 400)
        {
            if ($body !== '' && $body !== false)
            {
                $decoded = json_decode($body, true);
                if (is_array($decoded))
                {
                    $msg = $decoded['detail'] ?? $decoded['message'] ?? 'Unknown error';
                    $code = $decoded['error'] ?? $this->lastHttpCode;
                    $this->lastError = "HTTP {$code}: {$msg}";
                }
                else
                {
                    $this->lastError = "HTTP {$this->lastHttpCode}";
                }
            }
            else
            {
                $this->lastError = "HTTP {$this->lastHttpCode}";
            }
            return null;
        }

        $this->lastError = null;

        if ($body === '' || $body === false)
        {
            if ($this->lastHttpCode === 204 || $this->lastHttpCode === 200)
            {
                return true;
            }
            return null;
        }

        $decoded = json_decode($body, true);
        if ($decoded === null && json_last_error() !== JSON_ERROR_NONE)
        {
            $this->lastError = 'JSON decode error: ' . json_last_error_msg()
                . ' (raw: ' . substr($body, 0, 200) . ')';
            return null;
        }

        return $decoded;
    }

    // --- Helpers ---------------------------------------------------------------

    private function isAlreadyExists()
    {
        return $this->lastError !== null
            && (strpos($this->lastError, 'already have such entry') !== false
                || strpos($this->lastError, 'ALREADY_EXISTS') !== false);
    }

    public function getLastError()
    {
        return $this->lastError;
    }

    public function getLastHttpCode()
    {
        return $this->lastHttpCode;
    }
}
