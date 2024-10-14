#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Metaregistrar\EPP\atEppConnection;
use Metaregistrar\EPP\atEppPollRequest;
use Metaregistrar\EPP\eppException;

$opts = [
    'server:',
    'delete-after-poll',
    'cltrid:',
    'logdir:',
    'logfile',
    'nossl',
];

$params = getopt('', $opts);

$serverstring = $params['server'] ?? '';
$deleteafterpoll = isset($params['delete-after-poll']);

// Ensure required parameters are there
if (!$serverstring) {
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
    $connection->setVerifyPeer(false);

    if ($logging) {
        $connection->setLogFile(rtrim($logdir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . date('Y-m-d') . '.log');
    }
    $connected = $connection->connect();
    $connection->setUsername($username);
    $connection->setPassword($password);
    $connected = $connection->login();

    $request = new atEppPollRequest(atEppPollRequest::POLL_REQ);
    if ($cltrid = ($params['cltrid'] ?? '')) {
		if (strlen($cltrid) > 64 || strlen($cltrid) < 4 ) {
			fwrite(STDERR, "--cltrid must be between 3 and 64 characters\n");
			exit -1;
		}
        $request->sessionid = $cltrid;
        $request->addSessionId();
    }

    $response = $connection->request($request);

    $messagecount = $response->getMessageCount();

	echo "SUCCESS: \n";
	echo "Messages waiting: $messagecount\n";

	if ( $messagecount > 0 ) {
		echo "\n";

        $msgid = $response->getMessageId();
		echo "message id: $msgid\n";

        $date = $response->getMessageDate();
        if ($time = strtotime($date)) {
            $date = date('c', $time);
        }

        echo "Queue-Date: $date\n";
		printf("message desc: %s\n", $response->getDesc());

		printf("message type: %s\n", $response->getType());
		printXML($response);

		if ($deleteafterpoll) {
            $request = new atEppPollRequest(atEppPollRequest::POLL_ACK, $msgid);
            if ($cltrid = ($params['cltrid'] ?? '')) {
                $request->sessionid = $cltrid;
                $request->addSessionId();
            }

            $response = $connection->request($request);

            if ($response->Success()) {
				echo "\nMessage $msgid deleted\n";
			}
		}
	}

    echo "\nATTR: clTRID: " . $response->getClientTransactionId() . "\n";
    echo "ATTR: svTRID: " . $response->getServerTransactionId() . "\n";

    $connection->logout();
    $connection->disconnect();

} catch (eppException $e) {
    echo 'FAILED: ' . $e->getCode() . "\n";
    echo 'Poll message failed: ' . $e->getMessage() . "\n\n";
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

function printXML($node, $prefix = '') {
    foreach ($node->childNodes as $child) {
        if ($child->nodeName === "#text") {
            continue;
        }

        $name = $child->nodeName;
        if ($child->hasAttributes() && in_array($name, ['condition', 'result'])) {
            foreach ($child->attributes as $attr) {
                echo $name, " ", $attr->name, ": ", $attr->value, "\n";
            }
        }

        if ($child->hasChildNodes()) {
            printXML($child, "$name ");
            if (preg_match("/\n/", $child->textContent)) {
                continue;
            }
        }

        if (in_array($name, ['msg', 'details', 'clTRID', 'svTRID'])) {
            echo $prefix, $name, ": ", $child->textContent, "\n";
        }
    }
}

function usage() {
    echo <<<END

usage:

 pollmessage  --server <user>:<pass>@<host>:<port> \
              [--delete-after-poll]
              [--cltrid <cltrid>]
              [--logdir <directory>]

END;

    exit -1;
}
