<?php
/**
 * waros — Wazuh Active Response for MikroTik RouterOS 7 firewall blocking
 *
 * Normal mode: receives "add" commands via STDIN (Wazuh agent pipe),
 * creates firewall address-list entries on RouterOS 7 via REST API, exits.
 *
 * Test/debug modes (no STDIN required):
 *   --test          Block a random safe IP to verify router connectivity
 *   --calc-level    Calculate effective level and block timeout
 *   --debug-syslog  Send test message to syslog
 *
 * Reads STDIN with stream_select timeout (prevents pipe-blocking deadlock).
 * Writes "{}\n" to STDOUT before exit as safety against execd deadlock.
 *
 * Exit codes: 0 = success, 1 = failure
 * Compatible with PHP 7.4+ (typed properties via CliOptio)
 */

define('PROGRAM_VERSION', '1.2.0');
define('PROGRAM_NAME', 'waros');
define('MAX_STDIN_LINES', 1000);
define('STDIN_READ_TIMEOUT', 3);

// Base directory: phar — path to executable on disk, source — __DIR__
$BASE_DIR = Phar::running(false) !== ''
    ? dirname(Phar::running(false))
    : __DIR__;

require_once __DIR__ . '/CliOptio.php';
require_once __DIR__ . '/RosRestClient.php';
require_once __DIR__ . '/BlockManager.php';

// ============================================================================
// CLI setup via CliOptio
// ============================================================================
$mode = null;            // 'test' | 'calc-level' | 'debug-syslog' | null
$calcLevel = null;       // int value from --calc-level
$calcFiredtimes = 1;     // int value from --firedtimes (default 1)
$configPath = null;       // string from --config

$cli = new CliOptio();
$cli->SetErrorExitCode(1);
$cli->SetProgrammDescription(
    PROGRAM_NAME . ' v' . PROGRAM_VERSION . ' — Wazuh Active Response for MikroTik RouterOS 7 (REST API)'
);
$cli->UseInternalHelp();

// --- Mode options (mutually exclusive) --------------------------------------

$cli->DeclareOption(null, 'test');
$cli->SetOptionDescription('test',
    'Test mode: create a real firewall rule on the router with a random safe IP (198.51.100.0/24, RFC 5737) and 5-minute timeout. Verifies router connectivity, REST API authentication and rule creation. Comment: "test run". No STDIN read.'
);
$cli->SetOptionUnique('test');
$cli->SetOptionConflictGroup('test', 'mode');
$cli->SetOptionCallbackHandler('test', function ($v, $opts) use (&$mode) {
    $mode = 'test';
});

$cli->DeclareOption(null, 'calc-level');
$cli->SetOptionValueMode('calc-level', CliOptio::VALUE_REQUIRED);
$cli->SetOptionDescription('calc-level',
    'Calculate effective level and block timeout for the given Wazuh rule level. Uses --firedtimes (default 1) and config coefficients (timeout, escalation, max, firedtimes_divisor). Prints full computation to STDOUT. No STDIN read.'
);
$cli->SetOptionUnique('calc-level');
$cli->SetOptionConflictGroup('calc-level', 'mode');
$cli->SetOptionCallbackHandler('calc-level', function ($v, $opts) use (&$mode, &$calcLevel, &$calcFiredtimes) {
    $mode = 'calc-level';
    if (!is_numeric($v))
    {
        fwrite(STDERR, "ERROR: --calc-level requires a numeric value, got: {$v}\n");
        exit(1);
    }
    $calcLevel = (int)$v;
    if (isset($opts['firedtimes']))
    {
        $calcFiredtimes = (int)$opts['firedtimes'];
    }
});

$cli->DeclareOption(null, 'firedtimes');
$cli->SetOptionValueMode('firedtimes', CliOptio::VALUE_REQUIRED);
$cli->SetOptionDescription('firedtimes',
    'Rule firedtimes count for --calc-level (default: 1). Ignored without --calc-level.'
);
$cli->SetOptionUnique('firedtimes');

$cli->DeclareOption(null, 'debug-syslog');
$cli->SetOptionDescription('debug-syslog',
    'Send a test message to syslog using the configured facility. Verifies that syslog is working and the message reaches the log destination. No STDIN read.'
);
$cli->SetOptionUnique('debug-syslog');
$cli->SetOptionConflictGroup('debug-syslog', 'mode');
$cli->SetOptionCallbackHandler('debug-syslog', function ($v, $opts) use (&$mode) {
    $mode = 'debug-syslog';
});

// --- General options --------------------------------------------------------

$cli->DeclareOption('c', 'config');
$cli->SetOptionValueMode('config', CliOptio::VALUE_REQUIRED);
$cli->SetOptionDescription('config',
    'Path to config file. Default: auto-detect from WAROS_CONF env, /etc/waros.conf, /var/ossec/etc/waros.conf, or ./waros.conf.'
);
$cli->SetOptionUnique('config');
$cli->SetOptionCallbackHandler('config', function ($v, $opts) use (&$configPath) {
    $configPath = $v;
});

$cli->SetHelpTextTop('Modes (mutually exclusive; skip STDIN reading):');
$cli->SetHelpTextBottom(
    'Without mode flags: reads NDJSON from STDIN (normal Wazuh agent operation).'
);

// Parse CLI — exits on --help or validation errors
$opts = $cli->RunProcessing();

// ============================================================================
// Configuration
// ============================================================================

function loadConfig(?string $path = null): array
{
    if ($path === null)
    {
        $path = getenv('WAROS_CONF');
        if ($path !== false && $path !== '')
        {
            if (!file_exists($path))
            {
                fwrite(STDERR, "ERROR: WAROS_CONF=\"{$path}\" not found\n");
                exit(1);
            }
        }
        else
        {
            foreach (['/etc/waros.conf', '/var/ossec/etc/waros.conf', $GLOBALS['BASE_DIR'] . '/waros.conf'] as $candidate)
            {
                if (file_exists($candidate))
                {
                    $path = $candidate;
                    break;
                }
            }
        }
    }

    if ($path !== null && !file_exists($path))
    {
        fwrite(STDERR, "ERROR: Config file not found: {$path}\n");
        exit(1);
    }

    if ($path === null)
    {
        fwrite(STDERR, "ERROR: Config file not found.\n");
        fwrite(STDERR, "Searched: /etc/waros.conf, /var/ossec/etc/waros.conf, " . $GLOBALS['BASE_DIR'] . "/waros.conf\n");
        fwrite(STDERR, "Or set environment variable: WAROS_CONF=/path/to/waros.conf\n");
        exit(1);
    }

    $cfg = parse_ini_file($path, true, INI_SCANNER_TYPED);
    if ($cfg === false)
    {
        fwrite(STDERR, "ERROR: Failed to parse config file: {$path}\n");
        exit(1);
    }

    $cfg = array_change_key_case($cfg, CASE_LOWER);

    foreach (['routeros/ip', 'routeros/user', 'routeros/password'] as $key)
    {
        list($section, $field) = explode('/', $key);
        if (!isset($cfg[$section][$field]) || trim($cfg[$section][$field]) === '')
        {
            fwrite(STDERR, "ERROR: Missing required config field: {$key}\n");
            exit(1);
        }
    }

    return $cfg;
}

$cfg = loadConfig($configPath);

$rosConfig = $cfg['routeros'];
$blockConfig = $cfg['block'] ?? [];
$logConfig = $cfg['logging'] ?? [];

$ros = new RosRestClient($rosConfig);
$manager = new BlockManager($ros, array_merge($blockConfig, $logConfig));

// ============================================================================
// Mode handlers (each exits on completion)
// ============================================================================

if ($mode !== null)
{
    switch ($mode)
    {
        case 'test':
            waros_handle_test($ros, $blockConfig);
            break;
        case 'calc-level':
            waros_handle_calc_level($manager, $calcLevel, $calcFiredtimes);
            break;
        case 'debug-syslog':
            waros_handle_debug_syslog($manager);
            break;
    }
    exit(0);
}

// --- TTY guard (normal/pipe mode only) --------------------------------------
if (function_exists('stream_isatty') && stream_isatty(STDIN))
{
    fwrite(STDERR, PROGRAM_NAME . " v" . PROGRAM_VERSION
        . " — Wazuh Active Response for MikroTik RouterOS 7\n");
    fwrite(STDERR, "This program is designed to run via Wazuh agent (STDIN pipe).\n");
    fwrite(STDERR, "Run with --help for available test/debug modes and options.\n");
    exit(0);
}

// ============================================================================
// Normal operation: read NDJSON from STDIN
// ============================================================================

$exitCode = 0;
$lineNum = 0;
$hadData = false;

// stream_select with timeout prevents eternal block on open pipe.
// execd writes alert + "continue" but may not close the write-end.
while (true)
{
    $r = [STDIN];
    $w = null;
    $e = null;
    $changed = @stream_select($r, $w, $e, STDIN_READ_TIMEOUT);

    if ($changed === false || $changed === 0)
    {
        break;
    }

    $line = fgets(STDIN);
    if ($line === false)
    {
        break;
    }

    $lineNum++;

    if ($lineNum > MAX_STDIN_LINES)
    {
        fwrite(STDERR, "ERROR: STDIN exceeded " . MAX_STDIN_LINES
            . " lines (line {$lineNum}), aborting.\n");
        $exitCode = 1;
        break;
    }

    $input = parseLine($line, $lineNum);
    if ($input === null)
    {
        continue;
    }

    $hadData = true;

    $result = $manager->addBlock($input);
    if ($result !== 0 && $exitCode === 0)
    {
        $exitCode = $result;
    }
}

if (!$hadData)
{
    fwrite(STDERR, "WARNING: No valid commands received on STDIN\n");
}

// Safety: satisfy execd stdout read if timeout_allowed=yes
fwrite(STDOUT, "{}\n");

exit($exitCode);

// ============================================================================
// Mode handler functions
// ============================================================================

/**
 * Test mode: block a random safe IP on the router.
 * Verifies router connectivity, authentication, and rule creation.
 * Uses RFC 5737 TEST-NET-2 (198.51.100.0/24) — safe for testing.
 */
function waros_handle_test(RosRestClient $ros, array $blockConfig): void
{
    $listName = $blockConfig['list_name'] ?? 'wazuh-blocked';

    // Random IP from TEST-NET-2 (198.51.100.0/24, RFC 5737)
    $octet = random_int(1, 254);
    $testIp = '198.51.100.' . $octet;

    $timestamp = gmdate('Y-m-d\TH:i:s\Z');
    $comment = "waros test | {$timestamp} | test run";

    fwrite(STDERR, "[TEST] Sending block request to router\n");
    echo "IP:      {$testIp} (RFC 5737 TEST-NET-2, safe range)\n";
    echo "List:    {$listName}\n";
    echo "Timeout: 5m\n";
    echo "Comment: {$comment}\n";
    echo "\n";

    $result = $ros->addAddress($listName, $testIp, $comment, '5m');

    if ($result === RosRestClient::ALREADY_EXISTS)
    {
        fwrite(STDERR, "[TEST] Entry already exists on router\n");
        echo "Result: entry already exists on router\n";
        echo "  (the random IP collided with a previous test block; try again)\n";
        exit(0);
    }

    if ($result === null)
    {
        fwrite(STDERR, "[TEST] FAILED — " . $ros->getLastError() . "\n");
        fwrite(STDERR, "ERROR: Router request failed\n");
        exit(1);
    }

    $idStr = is_string($result) ? " (id={$result})" : '';
    fwrite(STDERR, "[TEST] SUCCESS — blocked {$testIp}{$idStr}\n");
    echo "Result: SUCCESS — blocked {$testIp}{$idStr}\n";
    echo "\n";
    echo "Note: test block with 5m timeout. Remove manually from router if needed.\n";
    exit(0);
}

/**
 * Calc-level mode: compute effective level and block timeout.
 * Shows full computation using config coefficients.
 */
function waros_handle_calc_level(BlockManager $manager, int $level, int $firedtimes): void
{
    $bc = $manager->getBlockConfig();
    $effLevel = $manager->calcEffectiveLevel($level, $firedtimes);
    $ttl = $manager->calcTimeout($effLevel);
    $bonus = intdiv($firedtimes, $bc['firedtimes_divisor']);

    echo "Config:\n";
    echo "  timeout_mode       = {$bc['timeout_mode']}\n";
    echo "  base_timeout       = {$bc['base_timeout']} ({$bc['base_seconds']}s)\n";
    echo "  escalation         = {$bc['escalation']}\n";
    echo "  max_timeout        = {$bc['max_timeout']} ({$bc['max_seconds']}s)\n";
    echo "  firedtimes_divisor = {$bc['firedtimes_divisor']}\n";
    echo "\n";

    echo "Input:\n";
    echo "  rule.level     = {$level}\n";
    echo "  firedtimes     = {$firedtimes}\n";
    echo "\n";

    echo "Calculation:\n";
    echo "  effective_level = {$level} + floor({$firedtimes} / {$bc['firedtimes_divisor']})"
        . " = {$level} + {$bonus} = {$effLevel}\n";

    if ($bc['base_seconds'] === 0)
    {
        echo "  base_timeout is 0 — blocks are PERMANENT (no timeout)\n";
        echo "\n";
        echo "Result:\n";
        echo "  effective_level = {$effLevel}\n";
        echo "  timeout         = permanent\n";
        exit(0);
    }

    if ($bc['timeout_mode'] === 'exponential')
    {
        // base * escalation^(level-1)
        $rawSec = (int)($bc['base_seconds'] * pow($bc['escalation'], max($effLevel, 1) - 1));
        $expVal = max($effLevel, 1) - 1;
        echo "  timeout_raw = {$bc['base_seconds']} * {$bc['escalation']}^({$expVal})"
            . " = {$bc['base_seconds']} * " . number_format(pow($bc['escalation'], $expVal), 6)
            . " = {$rawSec}s";
    }
    else
    {
        // linear: base * max(level, 1) * escalation
        $rawSec = (int)($bc['base_seconds'] * max($effLevel, 1) * $bc['escalation']);
        echo "  timeout_raw = {$bc['base_seconds']} * max({$effLevel}, 1) * {$bc['escalation']}"
            . " = {$rawSec}s";
    }

    $capped = ($rawSec > $bc['max_seconds']);
    if ($capped)
    {
        echo " > max({$bc['max_seconds']}s), capped";
    }
    echo "\n";
    echo "\n";

    echo "Result:\n";
    echo "  effective_level = {$effLevel}\n";
    echo "  timeout         = {$ttl}" . ($capped ? ' (capped at max)' : '') . "\n";
    exit(0);
}

/**
 * Debug-syslog mode: send a test message to syslog.
 * Verifies logging configuration (facility, destination).
 */
function waros_handle_debug_syslog(BlockManager $manager): void
{
    $ts = gmdate('Y-m-d\TH:i:s\Z');
    $msg = "waros debug-syslog test | {$ts}";

    fwrite(STDERR, "[DEBUG-SYSLOG] Sending test message to syslog\n");
    echo "Message: {$msg}\n";
    echo "\n";

    $manager->sendTestSyslog($msg);

    fwrite(STDERR, "[DEBUG-SYSLOG] Sent\n");
    echo "Result: message sent to syslog (LOG_INFO)\n";
    echo "  Verify with: journalctl -t waros (systemd) or check your syslog destination.\n";
    exit(0);
}

// ============================================================================
// NDJSON parser
// ============================================================================

function parseLine(string $line, int $lineNum): ?array
{
    $line = trim($line);
    if ($line === '')
    {
        return null;
    }

    $data = json_decode($line, true);
    if ($data === null || !isset($data['command']))
    {
        return null;
    }

    $command = strtolower($data['command']);

    // Silently ignore execd protocol responses
    if (in_array($command, ['continue', 'abort'], true))
    {
        return null;
    }

    if ($command !== 'add')
    {
        fwrite(STDERR, "WARNING: Unknown command '{$data['command']}' on line {$lineNum}, skipping\n");
        return null;
    }

    if (!isset($data['parameters']['alert']))
    {
        fwrite(STDERR, "WARNING: Missing 'parameters.alert' on line {$lineNum}, skipping\n");
        return null;
    }

    return $data;
}
