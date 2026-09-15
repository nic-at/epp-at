#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use EppAt\EppHelper;
use Metaregistrar\EPP\atEppPollRequest;

$params = EppHelper::getOpt([
    'delete-after-poll'
]);

EppHelper::checkParams($params);

EppHelper::execute($params, function($connection, $params) {
    $request = EppHelper::prepareRequest($params, atEppPollRequest::class, atEppPollRequest::POLL_REQ);

    $response = $connection->request($request);

    $messagecount = $response->getMessageCount();

    $deleteafterpoll = isset($params['delete-after-poll']);

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
            $request = EppHelper::prepareRequest(
                $params, 
                atEppPollRequest::class, 
                atEppPollRequest::POLL_ACK
            );
            $request = new atEppPollRequest(atEppPollRequest::POLL_ACK, $msgid);

            $response = $connection->request($request);

            if ($response->Success()) {
				echo "\nMessage $msgid deleted\n";
			}
		}
	}

    echo "\nATTR: clTRID: " . $response->getClientTransactionId() . "\n";
    echo "ATTR: svTRID: " . $response->getServerTransactionId() . "\n";

});

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

    exit(-1);
}
