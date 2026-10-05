<?php

namespace EppAt;

use atEppException;
use Dotenv\Dotenv;
use Metaregistrar\EPP\atEppConnection;
use Metaregistrar\EPP\atEppContact;
use Metaregistrar\EPP\atEppVerificationReport;
use Metaregistrar\EPP\eppContactPostalInfo;
use Metaregistrar\EPP\eppException;
use Metaregistrar\EPP\eppRequest;
use ReflectionFunction;

class EppHelper {

    public static function getOpt(array $extra_fields=[]) : array {
        $opt_config = self::getOptConfig($extra_fields);
        $params = getopt('', $opt_config);
        
        $dotenv = Dotenv::createImmutable(getcwd(), $params["env-file"] ?? ".env");
        $dotenv->safeLoad();

        foreach($opt_config as $key) {
            $opt_key = self::optKey($key);
            $env_key = self::dotEnvKey($key);
            if(!array_key_exists($opt_key, $params) && array_key_exists($env_key, $_ENV)) {
                if(str_ends_with($key, ":")) {
                    # option accepts a value
                    $params[$opt_key] = $_ENV[$env_key];
                }
                else
                {
                    # option does not accept a value
                    # we recreate the behavior of getOpt here - if a flag is set, the value
                    # is false - otherwise the key is not set at all
                    $value = trim(strtolower($_ENV[$env_key]));
                    if($value == "true" || $value == "yes" || $value == "1") {
                        $params[$opt_key] = false;
                    }
                }
            }
        }
        
        return $params;
    }

    public static function getOptConfig(array $extra_fields=[]) : array {
        return array_merge(
            self::getConnectionCliArgs(),
            $extra_fields
        );
    }

    public static function getConnectionCliArgs() : array {
        return [
            'env-file:',
            'server:',
            'logdir:',
            'logfile:',
            'nossl',
            'skip-verify-peer',
            'cltrid:',
            'command:',
        ];
    }

    public static function connect(array $params, bool $skip_login=false) : atEppConnection {
        $serverstring = $params['server'] ?? '';

        // Ensure required parameters are there
        if (!$serverstring) {
            usage();
        }

        $connection_params = self::parseServerString($serverstring);

        // Check nossl
        $protocol = "ssl";
        if (isset($params['nossl'])) {
            fwrite(STDERR, "WARNING: --nossl is set! Connecting with plain TCP!\n");
            $protocol = "tcp";
        }

        $logging = false;

        // Check logfile
        if (isset($params['logfile'])) {
            fwrite(STDERR, "The option --logfile is deprecated\n");
            fwrite(STDERR, "use --logdir <directory> instead\n");
            exit(-1);
        }

        if ($logdir = ($params['logdir'] ?? '')) {
            $logging = true;
        }

        $connection = new atEppConnection($logging);
        $connection->setHostname("{$protocol}://{$connection_params['host']}");
        $connection->setPort(intval($connection_params['port'] ?? 700));
        $connection->setTimeout(10);

        if(isset($params['skip-verify-peer'])) {
            fwrite(STDERR, "WARNING: --skip-verify-peer is set! Skipping verification of server certificate!\n");
            $connection->setVerifyPeer(false);
        }

        if ($logging) {
            $connection->setLogFile(rtrim($logdir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . date('Y-m-d') . '.log');
        }

        if(!$connection->connect()) {
            fwrite(STDERR, "could not connect to EPP server\n");
            exit(-1);
        }

        $username = $connection_params["username"] ?? "";
        $password = $connection_params["password"] ?? "";

        if(($username != "") != ($password != "")) {
            fwrite(STDERR, "either both username and password must be set, or none of them\n");
            exit(-1);
        }

        if($username != "") $connection->setUsername($username);
        if($password != "") $connection->setPassword($password);

        if((!$skip_login) && $username !== "" && $password !== "") {
            $connection->login();
        }

        return $connection;
    }

    public static function execute(
        array $params, 
        callable $fn, 
        bool $skip_login = false, 
        bool $exit_on_error = true
    ) {
        try {
            try {
                $connection = EppHelper::connect($params, skip_login: $skip_login);
            } catch(eppException $e) {
                self::formatEppException($e);
                throw $e;
            }

            $reflection = new ReflectionFunction($fn);

            $call_args = [];
            foreach($reflection->getParameters() as $parameter) {
                $name = $parameter->getName();
                switch($name) {
                    case "connection":
                        $call_args[] = $connection;
                        break;
                    case "params":
                        $call_args[] = $params;
                        break;
                    default:
                        throw new EppHelperException("unknown parameter '$name' for callback \$fn");
                }
            }

            try {
                return call_user_func($fn, ...$call_args);
            } catch(eppException $e) {
                self::formatEppException($e);
                throw $e;
            } finally {
                if(!$connection->isLoggedin()) $connection->logout();
                $connection->disconnect();
            }
        } catch(eppException $e) {
            if($exit_on_error) exit(-1);
        }
    }

    public static function formatEppException(eppException $e) {
        echo $e->getMessage() . "\n";
        if ($reason = $e->getReason()) {
            self::checkAndPrintConditions(json_decode($reason, true));
        }
    }

    public static function setCltrid(?string $cltrid, eppRequest &$request) {
        if ($cltrid) {
            $request->sessionid = $cltrid;
            $request->addSessionId();
        }
    }

    
    public static function checkParams(array $params) {
        self::checkCltrid($params);
    }

    public static function checkCltrid(array $params) : ?string {
        if ($cltrid = ($params['cltrid'] ?? '')) {
            if (strlen($cltrid) > 64 || strlen($cltrid) < 3 ) {
                fwrite(STDERR, "--cltrid must be between 3 and 64 characters\n");
                exit(-1);
            }
            return $cltrid;
        }
        return null;
    }

    public static function prepareRequest(array $params, $request_class, ...$args) : eppRequest {
        $request = new $request_class(...$args);
        self::setCltrid(self::checkCltrid($params), $request);
        return $request;
    }

    public static function checkContactData(array $params) : bool {
        $name = $params['name'] ?? '';
        $city = $params['city'] ?? '';
        $country = $params['country'] ?? '';
        $postalcode = $params['postalcode'] ?? '';
        $province = $params['province'] ?? '';
        $email = $params['email'] ?? '';
        $type = $params['type'] ?? '';

        $uniqueargs = ['name', 'org', 'city', 'postalcode', 'province', 'country', 'phone', 'voice', 'email', 'type'];

        foreach ($uniqueargs as $uarg) {
            if (is_array($params[$uarg] ?? null)) {
                echo "\nError: only one --$uarg argument allowed\n";
                return false;
            }
        }

        if (!($name && $city && $postalcode && $country && $email && $type)) {
            echo "\nError: missing required argument";
            return false;
        }

        // Validate the contact type
        if (!in_array($type, ['privateperson', 'organisation', 'role'])) {
            fwrite(STDERR, "--type must be one Parameter out off \"privateperson, organisation, role\"\n");
            return false;
        }

        return true;
    }

    static function checkAndPrintConditions($conditions) {
        if (!is_array($conditions)) return false;
        foreach ($conditions as $condition) {
            if (!empty($condition['message'])) {
                echo "Msg: {$condition['message']}\n";
            }
            if (!empty($condition['details'])) {
                echo "Details: {$condition['details']}\n";
            }
            echo "\n";
        }
    }

    static function toPostalInfo(array $params) : ?eppContactPostalInfo {
        $name = $params['name'] ?? '';
        $org = $params['org'] ?? null;
        $street = $params['street'] ?? '';
        $city = $params['city'] ?? '';
        $country = $params['country'] ?? '';
        $postalcode = $params['postalcode'] ?? '';
        $province = $params['province'] ?? '';

        return new eppContactPostalInfo($name, $city, $country, $org, 
                                        $street, $province, $postalcode);
    }

    static function toContact(
        array $params, 
        ?eppContactPostalInfo $postalInfo = null
    ) {
        if($postalInfo === null) $postalInfo = EppHelper::toPostalInfo($params);
        
        $phone = $params['voice'] ?? '';
        $email = $params['email'] ?? '';
        $type = $params['type'] ?? '';

        $verification_report = [
            'result'    => $params['verification-report-result']    ?? null,
            'date'      => $params['verification-report-date']      ?? null,
            'method'    => $params['verification-report-method']    ?? null,
            'reference' => $params['verification-report-reference'] ?? null,
            'agent'     => $params['verification-report-agent']     ?? null,
        ];

        $verification = null;
        if ($verification_report['result'] && $verification_report['date']) {
            $verification = new atEppVerificationReport(
                $verification_report['result'],
                $verification_report['date'],
                $verification_report['method'],
                $verification_report['reference'],
                $verification_report['agent']
            );
        }
        
        $contact = new atEppContact($postalInfo, $type, $email, $phone, null, 
                                    false, false, false, null, null, 
                                    $verification);
        return $contact;
    }

    private static function parseServerString(string $serverstring) {
        // Parsing the server string
        if (preg_match('/^(?:(?<username>[\w\d]+):(?<password>[\S:@]+)@)?(?<host>[\p{L}\.\-0-9]+)(?::(?<port>\d+))?$/', $serverstring, $matches)) {
            return $matches;
        }
        else
        {
            fwrite(STDERR, "could not parse server string '$serverstring' - expected format [<user>:<pass>@]<host>[:<port>]\n");
            exit(-1);
        }
    }

    private static function optKey(string $opt_key) {
        return rtrim($opt_key, ":");
    }

    private static function dotEnvKey(string $opt_key) {
        return str_replace("-", "_", rtrim($opt_key, ":"));
    }
}