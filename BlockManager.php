<?php
/**
 * BlockManager — blocking logic for Wazuh Active Response
 *
 * Receives "add" command, resolves srcip from alert, blocks via RouterOS REST API.
 * Local cache (flat file) avoids redundant API calls for repeat alerts.
 *
 * Timeout: effective_level = rule.level + floor(firedtimes / divisor)
 *          timeout = base * max(level, 1) * escalation, capped at max
 *
 * Cache format: ip<TAB>list<TAB>timestamp<TAB>timeout
 * Compatible with PHP 7.3+
 */

class BlockManager
{
    private $ros;
    private $listName;
    private $commentTemplate;
    private $baseTimeout;
    private $escalation;
    private $maxTimeout;
    private $firedtimesDivisor;
    private $timeoutMode;
    private $logLevel;
    private $srcipSources;
    private $cacheFile;

    const LOG_ERROR = 0;
    const LOG_WARN  = 1;
    const LOG_INFO  = 2;
    const LOG_DEBUG = 3;

    private static $LEVEL_MAP = [
        'ERROR' => self::LOG_ERROR,
        'WARN'  => self::LOG_WARN,
        'INFO'  => self::LOG_INFO,
        'DEBUG' => self::LOG_DEBUG,
    ];

    public function __construct(RosRestClient $ros, array $config)
    {
        $this->ros = $ros;
        $this->listName = $config['list_name'] ?? 'wazuh-blocked';
        $this->commentTemplate = $config['comment_template'] ?? '{rule} | {datetime} | {description}';
        $this->baseTimeout = $config['timeout'] ?? '1d';
        $this->escalation = (float)($config['timeout_escalation'] ?? 1.5);
        $this->maxTimeout = $config['timeout_max'] ?? '30d';
        $this->firedtimesDivisor = (int)($config['firedtimes_divisor'] ?? 50);
        $this->timeoutMode = strtolower($config['timeout_mode'] ?? 'linear');
        $this->cacheFile = $config['cache_file'] ?? sys_get_temp_dir() . '/waros_cache.txt';

        // srcip resolution — dot-separated paths into alert data
        $sourcesRaw = $config['srcip_sources'] ?? 'srcip, data.srcip, data.transaction.client_ip';
        $this->srcipSources = array_map('trim', explode(',', $sourcesRaw));
        $this->srcipSources = array_values(array_filter($this->srcipSources, function ($s)
        {
            return $s !== '';
        }));

        $logLevel = $config['level'] ?? 'INFO';
        $this->logLevel = self::$LEVEL_MAP[$logLevel] ?? self::LOG_INFO;

        $facility = $config['facility'] ?? 'LOG_LOCAL0';
        $facilityConst = 'LOG_' . strtoupper($facility);
        $facilityVal = defined($facilityConst) ? constant($facilityConst) : LOG_LOCAL0;
        openlog('waros', LOG_PID, $facilityVal);
    }

    // --- Main operation -------------------------------------------------------

    /**
     * Process an add-block command from Wazuh
     *
     * 1. Resolve srcip from alert data
     * 2. Check cache — skip if recently blocked and not expired
     * 3. POST to RouterOS REST API
     * 4. Update cache on success
     *
     * @param array $alert Full Wazuh alert JSON (the "parameters" object)
     * @return int 0 on success, 1 on error
     */
    public function addBlock(array $alert)
    {
        $p = $alert['parameters']['alert'] ?? [];
        $srcIp = $this->resolveSrcIp($p);

        if ($srcIp === null)
        {
            $ruleId = $p['rule']['id'] ?? 'unknown';
            $agentName = $p['agent']['name'] ?? 'unknown';
            $this->log("No srcip found for rule={$ruleId} agent={$agentName} (sources: "
                . implode(', ', $this->srcipSources) . ")", 'ERROR');
            return 1;
        }

        if (!$this->validateIp($srcIp))
        {
            $this->log("Invalid IP address: {$srcIp}", 'ERROR');
            return 1;
        }

        // Never block the agent's own IP
        $agentIp = $p['agent']['ip'] ?? null;
        if ($agentIp !== null && $agentIp === $srcIp)
        {
            $agentName = $p['agent']['name'] ?? 'unknown';
            $this->log("Skipping block: srcip {$srcIp} equals agent IP "
                . "(agent={$agentName})", 'WARN');
            return 0;
        }

        // Calculate timeout from alert data
        $effectiveLevel = $this->calculateEffectiveLevel($p);
        $timeout = $this->calculateTimeout($effectiveLevel);
        $displayTtl = ($timeout !== '') ? $timeout : 'permanent';

        // Check cache — skip if recently blocked and not expired
        if ($this->isCacheFresh($srcIp, $this->listName, $timeout))
        {
            $this->log("Blocked {$srcIp} (cached, skipped)", 'DEBUG');
            return 0;
        }

        // Build comment from template
        $vars = $this->extractTemplateVars($alert, $srcIp, $effectiveLevel, $p);
        $comment = $this->renderComment($vars, $displayTtl);

        // POST to RouterOS
        $result = $this->ros->addAddress($this->listName, $srcIp, $comment, $timeout);

        if ($result === RosRestClient::ALREADY_EXISTS)
        {
            $this->cacheSet($srcIp, $this->listName, $timeout);
            $levelRaw = (int)($p['rule']['level'] ?? 1);
            $firedtimesRaw = (int)($p['rule']['firedtimes'] ?? 1);
            $bonus = intdiv($firedtimesRaw, $this->firedtimesDivisor);
            $this->log("Blocked {$srcIp} (already on router, lvl={$effectiveLevel}={$levelRaw}+{$bonus}, ttl={$displayTtl})", 'INFO');
            return 0;
        }

        if ($result === null)
        {
            $this->log("Failed to add block for {$srcIp}: " . $this->ros->getLastError(), 'ERROR');
            return 1;
        }

        $this->cacheSet($srcIp, $this->listName, $timeout);
        $idStr = is_string($result) ? ", id={$result}" : '';
        $levelRaw = (int)($p['rule']['level'] ?? 1);
        $firedtimesRaw = (int)($p['rule']['firedtimes'] ?? 1);
        $bonus = intdiv($firedtimesRaw, $this->firedtimesDivisor);
        $this->log("Blocked {$srcIp} (new, lvl={$effectiveLevel}={$levelRaw}+{$bonus}, ttl={$displayTtl}{$idStr})", 'INFO');

        return 0;
    }

    // --- Cache ----------------------------------------------------------------
    // Flat file: ip<TAB>list<TAB>timestamp<TAB>timeout
    // Expired entries are purged on write.

    private function isCacheFresh($srcIp, $list, $timeout)
    {
        $entry = $this->cacheGet($srcIp);
        if ($entry === null)
        {
            return false;
        }

        if ($entry['list'] !== $list)
        {
            return false;
        }

        $timeoutSeconds = $this->parseTimeoutToSeconds($timeout);
        if ($timeoutSeconds <= 0)
        {
            return true; // permanent block
        }

        return (time() < $entry['timestamp'] + $timeoutSeconds);
    }

    private function cacheGet($srcIp)
    {
        $rows = $this->cacheReadAll();
        return $rows[$srcIp] ?? null;
    }

    private function cacheSet($srcIp, $list, $timeout)
    {
        $dir = dirname($this->cacheFile);
        if (!is_dir($dir))
        {
            @mkdir($dir, 0750, true);
        }

        $rows = $this->cacheReadAll();
        $rows[$srcIp] = [
            'list'      => $list,
            'timestamp' => time(),
            'timeout'   => $timeout,
        ];
        $this->cacheWriteAll($rows);
    }

    private function cacheReadAll()
    {
        if (!file_exists($this->cacheFile) || !is_readable($this->cacheFile))
        {
            return [];
        }

        $lines = file($this->cacheFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false)
        {
            return [];
        }

        $rows = [];
        foreach ($lines as $line)
        {
            $parts = explode("\t", $line);
            if (count($parts) >= 4)
            {
                $rows[$parts[0]] = [
                    'list'      => $parts[1],
                    'timestamp' => (int)$parts[2],
                    'timeout'   => $parts[3],
                ];
            }
        }

        return $rows;
    }

    private function cacheWriteAll(array $rows)
    {
        $dir = dirname($this->cacheFile);
        if (!is_dir($dir))
        {
            @mkdir($dir, 0750, true);
        }

        $now = time();
        $data = '';
        foreach ($rows as $ip => $entry)
        {
            $ttl = $this->parseTimeoutToSeconds($entry['timeout']);
            if ($ttl > 0 && ($entry['timestamp'] + $ttl) <= $now)
            {
                continue; // expired
            }
            $data .= $ip . "\t" . $entry['list'] . "\t" . $entry['timestamp'] . "\t" . $entry['timeout'] . "\n";
        }

        @file_put_contents($this->cacheFile, $data, LOCK_EX);
    }

    // --- Timeout calculation --------------------------------------------------

    /**
     * effective_level = rule.level + floor(firedtimes / divisor)
     */
    private function calculateEffectiveLevel(array $alertData)
    {
        $level = (int)($alertData['rule']['level'] ?? 1);
        $firedtimes = (int)($alertData['rule']['firedtimes'] ?? 1);
        return $level + intdiv($firedtimes, $this->firedtimesDivisor);
    }

    /**
     * Calculate block timeout based on configured mode.
     *
     * linear:      base * max(level, 1) * escalation, capped at max
     * exponential: base * escalation^(level-1), capped at max
     *
     * @return string RouterOS timeout (e.g. "15h", "3d") or "" for permanent
     */
    private function calculateTimeout($effectiveLevel)
    {
        if ($this->baseTimeout === '' || $this->baseTimeout === '0s' || $this->baseTimeout === '0')
        {
            return '';
        }

        $baseSeconds = $this->parseTimeoutToSeconds($this->baseTimeout);
        $maxSeconds = $this->parseTimeoutToSeconds($this->maxTimeout);

        if ($baseSeconds === 0)
        {
            return '';
        }

        $level = max((int)$effectiveLevel, 1);

        if ($this->timeoutMode === 'exponential')
        {
            // base * escalation^(level-1)
            // level=1 -> base (no bonus), level=2 -> base*esc, level=3 -> base*esc^2 ...
            $timeout = $baseSeconds * pow($this->escalation, $level - 1);
        }
        else
        {
            // linear (default, backward compatible)
            $timeout = $baseSeconds * $level * $this->escalation;
        }

        if ($timeout > $maxSeconds)
        {
            $timeout = $maxSeconds;
        }

        return $this->formatSecondsToTimeout((int)$timeout);
    }

    /**
     * Parse RouterOS timeout string to seconds
     * Supports: 1w, 1d, 1h, 1m, 1s, combinations like 1w2d3h
     */
    private function parseTimeoutToSeconds($timeout)
    {
        if ($timeout === '' || $timeout === '0s')
        {
            return 0;
        }

        $total = 0;
        $multipliers = ['w' => 604800, 'd' => 86400, 'h' => 3600, 'm' => 60, 's' => 1];

        if (preg_match_all('/(\d+)\s*(w|d|h|m|s)/i', $timeout, $matches, PREG_SET_ORDER))
        {
            foreach ($matches as $match)
            {
                $value = (int)$match[1];
                $unit = strtolower($match[2]);
                $total += $value * ($multipliers[$unit] ?? 0);
            }
        }

        return $total;
    }

    private function formatSecondsToTimeout($seconds)
    {
        if ($seconds <= 0)
        {
            return '';
        }

        $units = [
            ['w', 604800],
            ['d', 86400],
            ['h', 3600],
            ['m', 60],
            ['s', 1],
        ];

        $parts = [];
        foreach ($units as $unit)
        {
            $label = $unit[0];
            $divisor = $unit[1];
            if ($seconds >= $divisor)
            {
                $count = intdiv($seconds, $divisor);
                $parts[] = $count . $label;
                $seconds %= $divisor;
            }
        }

        return implode('', $parts);
    }

    // --- Comment rendering ----------------------------------------------------

    private function renderComment(array $vars, $ttl)
    {
        $vars['ttl'] = ($ttl !== '') ? $ttl : 'permanent';

        $comment = $this->commentTemplate;
        foreach ($vars as $key => $value)
        {
            $comment = str_replace('{' . $key . '}', $value, $comment);
        }

        // RouterOS comment limit is 1024 characters
        if (strlen($comment) > 1024)
        {
            $comment = substr($comment, 0, 1020) . '...';
        }

        return $comment;
    }

    // --- IP resolution --------------------------------------------------------

    private function resolveSrcIp(array $alertData)
    {
        foreach ($this->srcipSources as $path)
        {
            $value = $this->resolvePath($alertData, $path);
            if ($value !== null && $value !== '' && $this->validateIp($value))
            {
                $this->log("srcip resolved from '{$path}': {$value}", 'DEBUG');
                return $value;
            }
        }
        return null;
    }

    /**
     * Resolve dot-separated path into nested array
     * Examples: 'data.srcip' -> $data['data']['srcip']
     */
    private function resolvePath(array $data, string $path)
    {
        foreach (explode('.', $path) as $key)
        {
            if (!is_array($data) || !array_key_exists($key, $data))
            {
                return null;
            }
            $data = $data[$key];
        }
        return $data;
    }

    private function extractTemplateVars(array $alert, $srcIp, $effectiveLevel, array $alertData)
    {
        $agentId = $alertData['agent']['id'] ?? $alert['agent_id'] ?? '000';
        $agentName = $alertData['agent']['name'] ?? $agentId;
        $timestamp = $alertData['timestamp'] ?? $alert['timestamp'] ?? null;
        $level = (int)($alertData['rule']['level'] ?? 1);
        $firedtimes = (int)($alertData['rule']['firedtimes'] ?? 1);
        $levelBonus = intdiv($firedtimes, $this->firedtimesDivisor);

        return [
            'srcip'          => $srcIp,
            'rule'           => $alertData['rule']['id'] ?? '0',
            'description'    => !empty($alertData['rule']['description']) ? $alertData['rule']['description'] : 'no description',
            'agent_id'       => $agentId,
            'agent_name'     => $agentName,
            'datetime'       => $this->formatTimestamp($timestamp),
            'level'          => (string)$level,
            'firedtimes'     => (string)$firedtimes,
            'level_bonus'    => (string)$levelBonus,
            'effective_level'=> (string)$effectiveLevel,
        ];
    }

    private function formatTimestamp($ts)
    {
        if ($ts === null || $ts === '')
        {
            return gmdate('Y-m-d\TH:i:s\Z');
        }

        $dt = strtotime($ts);
        if ($dt === false)
        {
            return gmdate('Y-m-d\TH:i:s\Z');
        }

        return gmdate('Y-m-d\TH:i:s\Z', $dt);
    }

    private function validateIp($ip)
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    // --- Public interface for test/debug modes --------------------------------

    /**
     * Get block configuration values for external inspection.
     * Used by --calc-level mode to display the computation.
     *
     * @return array Associative array with base_timeout, base_seconds,
     *               escalation, max_timeout, max_seconds, firedtimes_divisor, list_name.
     */
    public function getBlockConfig(): array
    {
        return [
            'base_timeout'       => $this->baseTimeout,
            'base_seconds'       => $this->parseTimeoutToSeconds($this->baseTimeout),
            'escalation'         => $this->escalation,
            'max_timeout'        => $this->maxTimeout,
            'max_seconds'        => $this->parseTimeoutToSeconds($this->maxTimeout),
            'firedtimes_divisor' => $this->firedtimesDivisor,
            'list_name'          => $this->listName,
            'timeout_mode'       => $this->timeoutMode,
        ];
    }

    /**
     * Calculate effective level from rule level and firedtimes.
     * Formula: effective_level = level + floor(firedtimes / divisor)
     *
     * @param int $level      Wazuh rule level
     * @param int $firedtimes Rule hit count
     * @return int Effective level after escalation
     */
    public function calcEffectiveLevel(int $level, int $firedtimes): int
    {
        return $level + intdiv($firedtimes, $this->firedtimesDivisor);
    }

    /**
     * Calculate block timeout for a given effective level.
     * Uses the same logic as the private calculateTimeout().
     *
     * @param int $effectiveLevel Effective level (rule.level + escalation bonus)
     * @return string RouterOS timeout (e.g. "15h", "3d") or "" for permanent
     */
    public function calcTimeout(int $effectiveLevel): string
    {
        return $this->calculateTimeout($effectiveLevel);
    }

    /**
     * Send a test message to syslog (LOG_INFO priority).
     * Used by --debug-syslog mode to verify logging configuration.
     * Syslog is already opened by the constructor with the configured facility.
     *
     * @param string $message Message to send
     */
    public function sendTestSyslog(string $message): void
    {
        syslog(LOG_INFO, $message);
    }

    // --- Logging --------------------------------------------------------------

    private static $SYSLOG_MAP = [
        'ERROR' => LOG_ERR,
        'WARN'  => LOG_WARNING,
        'INFO'  => LOG_INFO,
        'DEBUG' => LOG_DEBUG,
    ];

    private function log($message, $level = 'INFO')
    {
        $levelNum = self::$LEVEL_MAP[$level] ?? self::LOG_INFO;
        if ($levelNum > $this->logLevel)
        {
            return;
        }

        fwrite(STDERR, '[' . $level . '] ' . $message . PHP_EOL);

        $syslogLevel = self::$SYSLOG_MAP[$level] ?? LOG_INFO;
        syslog($syslogLevel, $message);
    }
}
