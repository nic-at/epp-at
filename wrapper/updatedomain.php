#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Metaregistrar\EPP\atEppConnection;
use Metaregistrar\EPP\atEppUpdateDomainRequest;
use Metaregistrar\EPP\atEppUndeleteRequest;
use Metaregistrar\EPP\eppInfoDomainRequest;
use Metaregistrar\EPP\atEppContactHandle;
use Metaregistrar\EPP\atEppDomain;
use Metaregistrar\EPP\eppHost;
use Metaregistrar\EPP\eppSecdns;
use Metaregistrar\EPP\eppException;

$opts = [
    'server:',
    'domain:',
    'addns:',
    'delns:',
    'registrant:',
    'addtechc:',
    'deltechc:',
    'addsecdns:',
    'delsecdns:',
    'delsecdns-all',
    'restore',
    'authinfo:',
    'cltrid:',
    'logdir:',
    'logfile',
    'nossl',
];

$params = getopt('', $opts);

$serverstring = $params['server'] ?? '';
$domain = $params['domain'] ?? '';
$addns = (array) ($params['addns'] ?? []);
$delns = (array) ($params['delns'] ?? []);
$registrant = $params['registrant'] ?? null;
$addtechc = (array) ($params['addtechc'] ?? []);
$deltechc = (array) ($params['deltechc'] ?? []);
$addsecdns = (array) ($params['addsecdns'] ?? []);
$delsecdns = (array) ($params['delsecdns'] ?? []);
$delallsecdns = isset($params['delsecdns-all']);
$restore = isset($params['restore']);
$auth = $params['authinfo'] ?? null;

// Ensure required parameters are there
if (!($serverstring && $domain)) {
    usage();
}

// Check delsecdns
if ($delallsecdns && $delsecdns) {
	fwrite(STDERR, "\nEither --delsecdns-all or --delsecdns \"...\" allowed, not both of them\n");
	usage();
}

// Parsing the server string
if (!preg_match('/^([\w\d]+):([\S:@]+)@(\S+):(\d+)$/', $serverstring, $matches)) {
    fwrite(STDERR, "could not parse server string '$serverstring'\n");
    exit -1;
}
[, $username, $password, $hostname, $port] = $matches;

// Check nossl
if (isset($params['nossl'])) {
    echo "Warning: --nossl is deprecated and will be ignored ...\n";
}

try {
    $logging = false;

    // Check logfile
    if (isset($params['logfile'])) {
        fwrite(STDERR, "The option --logfile is deprecated\n");
        fwrite(STDERR, "use --logdir <directory> instead\n");
        exit -1;
    }

    if ($logdir = ($params['logdir'] ?? '')) {
        $logging = true;
    }

    $connection = new atEppConnection($logging);
    $connection->setHostname('ssl://' . $hostname);
    $connection->setPort($port);
    $connection->setTimeout(10);

    if ($logging) {
        $connection->setLogFile(rtrim($logdir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . date('Y-m-d') . '.log');
    }
    $connected = $connection->connect();
    $connection->setUsername($username);
    $connection->setPassword($password);
    $logged_in = $connection->login();

    // Run undelete request if restore is called
    if ($restore) {
        $request = new atEppUndeleteRequest(new atEppDomain($domain));
        if ($cltrid = ($params['cltrid'] ?? '')) {
            if (strlen($cltrid) > 64 || strlen($cltrid) < 4 ) {
                fwrite(STDERR, "--cltrid must be between 3 and 64 characters\n");
                exit -1;
            }
            $request->sessionid = $cltrid;
            $request->addSessionId();
        }
        $response = $connection->request($request);

        if ($response->Success()) {
            echo 'SUCCESS: ' . $response->getResultCode() . "\n";
        } else {
            echo 'FAILED: ' . $response->getResultCode() . "\n";
            echo 'Domain restore failed: ' . $response->getResultMessage() . "\n\n";
        }

        check_and_print_conditions($response->getExtensionResult());

        echo "\nATTR: clTRID: " . $response->getClTrId() . "\n";
        echo "ATTR: svTRID: " . $response->getSvTrId() . "\n";
    }

    if ($addns || $delns || $registrant || $addtechc || $deltechc || $addsecdns || $delsecdns || $delallsecdns || $auth) {

        $chg = new atEppDomain($domain);
        $add = $rem = null;

        if ($registrant) {
            $chg->setRegistrant(new atEppContactHandle($registrant, 'reg'));
        }

        if ($auth) {
            $chg->setAuthorisationCode($auth);
        }

        // Handle nameserver
        foreach ($delns as $ns) {
            if (!$rem) $rem = new atEppDomain($domain);
            $rem->addHost(new eppHost($ns));
        }

        foreach ($addns as $ns) {
            if (!$add) $add = new atEppDomain($domain);
            $host = explode('/', $ns);
            if (count($host) == 1) {
                $add->addHost(new eppHost($host[0]));
            } else {
                for ($i = 1; $i < count($host); $i++) {
                    if ($host[$i] && !filter_var($host[$i], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && !filter_var($host[$i], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                        fwrite(STDERR, $host[$i] . " is not a valid IPv4/IPv6 Address\n");
                        exit -1;
                    }
                    $add->addHost(new eppHost($host[0], $host[$i]));
                }
            }
        }

        // Handle techc
        foreach ($deltechc as $handle) {
            if (!$rem) $rem = new atEppDomain($domain);
            $rem->addContact(new atEppContactHandle($handle, 'tech'));
        }

        foreach ($addtechc as $handle) {
            if (!$add) $add = new atEppDomain($domain);
            $add->addContact(new atEppContactHandle($handle, 'tech'));
        }

        // Check secdns
        foreach ($addsecdns as $secdns) {
            $secdnsarray = array_reduce(explode(',', $secdns), function($carry, $item) {
                [$key, $value] = array_map('trim', explode('=>', $item));
                $carry[$key] = trim($value, "'\"");
                return $carry;
            }, []);
            if (!empty($secdnsarray['keyTag']) && !empty($secdnsarray['digestType']) && !empty($secdnsarray['digest']) && !empty($secdnsarray['alg'])) {
                $eppSecdns = new eppSecdns();
                $eppSecdns->setKeytag($secdnsarray['keyTag']);
                $eppSecdns->setDigestType($secdnsarray['digestType']);
                $eppSecdns->setDigest($secdnsarray['digest']);
                $eppSecdns->setAlgorithm($secdnsarray['alg']);
                if (!$add) $add = new atEppDomain($domain);
                $add->addSecdns($eppSecdns);
            }
        }

        foreach ($delsecdns as $secdns) {
            $secdnsarray = array_reduce(explode(',', $secdns), function($carry, $item) {
                [$key, $value] = array_map('trim', explode('=>', $item));
                $carry[$key] = trim($value, "'\"");
                return $carry;
            }, []);
            if (!empty($secdnsarray['keyTag']) && !empty($secdnsarray['digestType']) && !empty($secdnsarray['digest']) && !empty($secdnsarray['alg'])) {
                $eppSecdns = new eppSecdns();
                $eppSecdns->setKeytag($secdnsarray['keyTag']);
                $eppSecdns->setDigestType($secdnsarray['digestType']);
                $eppSecdns->setDigest($secdnsarray['digest']);
                $eppSecdns->setAlgorithm($secdnsarray['alg']);
                if (!$rem) $rem = new atEppDomain($domain);
                $rem->addSecdns($eppSecdns);
            }
        }

        if ($delallsecdns) {
            // In order to delete all the secdns we need to fetch them first
            $request = new eppInfoDomainRequest(new atEppDomain($domain));
            $response = $connection->request($request);

            if ($secdns = $response->getKeydata()) {
                if (!$rem) $rem = new atEppDomain($domain);
                foreach ($secdns as $n) {
                    $rem->addSecdns($n);
                }
            }
        }

        $request = new atEppUpdateDomainRequest($domain, $add, $rem, $chg, true);
        if ($cltrid = ($params['cltrid'] ?? '')) {
            if (strlen($cltrid) > 64 || strlen($cltrid) < 4 ) {
                fwrite(STDERR, "--cltrid must be between 3 and 64 characters\n");
                exit -1;
            }
            $request->sessionid = $cltrid;
            $request->addSessionId();
        }

        $response = $connection->request($request);

        if ($response->Success()) {
            echo 'SUCCESS: ' . $response->getResultCode() . "\n";
        } else {
            echo 'FAILED: ' . $response->getResultCode() . "\n";
            echo 'Domain update failed: ' . $response->getResultMessage() . "\n\n";
        }

        check_and_print_conditions($response->getExtensionResult());

        echo "\nATTR: clTRID: " . $response->getClTrId() . "\n";
        echo "ATTR: svTRID: " . $response->getSvTrId() . "\n";

    }

    $connection->logout();
    $connection->disconnect();

} catch (eppException $e) {
    echo $e->getMessage() . "\n";
    check_and_print_conditions(json_decode($e->getReason(), true));
    exit -1;
}

function check_and_print_conditions($conditions) {
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

function usage() {
    echo <<<END

usage:

 updatedomain  	--server <user>:<pass>@<host>:<port> \
                --domain <domain>
                [--addns <nsname>[/<ipaddr>[/<ipaddr>]]]
                [--delns <nsname>]
                [--registrant <registrant>]
                [--addtechc <tech-c>]
                [--deltechc <tech-c>]
                [--addsecdns "keyTag=>'12346', alg=>3, digestType=>1, digest=>'49FD46E6C4B45C55D4DD'"]
                [--delsecdns "keyTag=>'12346', alg=>3, digestType=>1, digest=>'49FD46E6C4B45C55D4DD'"]
                [--delsecdns-all]
                [--restore]
                [--authinfo \$'<authinfo>']
                [--cltrid <cltrid>]
                [--logdir <directory>]

Note: The Unix shell intercepts some special characters and tries to
      interpret them (f.e. \$). To pass an authInfo string with special
      characters to the EPP toolkit please encode the authInfo in the format
      \$'<authinfo>'. If you want to use a single quote within the authinfo
      string please escape it with a backslash (\\')

END;

    exit -1;
}
