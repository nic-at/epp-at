#!/usr/bin/env php
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use EppAt\EppHelper;

$params = EppHelper::getOpt(['newpassword:']);

$newpassword = $params['newpassword'] ?? [];

// Ensure required parameters are there
if (!$newpassword) {
    usage();
}

// Check password length
if (!xml_is_token($newpassword, 8, 16)) {
    fwrite(STDERR, " --newpassword must be between 8 and 16 characters\n");
    exit(-1);
};

EppHelper::execute(
    $params, 
    skip_login: true, 
    fn: function($connection) use($newpassword) {
        $connection->setNewPassword($newpassword);

        $connected = $connection->login();

        if ($connected) {
            echo "SUCCESS: The EPP-Password has been changed\n\n";
        }
    }
);

function xml_is_token($what, $min = null, $max = null) {
    // Return false if $what is not defined
    if (empty($what)) {
        return false;
    }

    // Return false if $what is an array or an object
    if (is_array($what) || is_object($what)) {
        return false;
    }

    // Return false if $what contains invalid characters
    if (preg_match('/[\r\n\t]/', $what)) {
        return false;
    }

    // Return false if $what starts or ends with whitespace, or has consecutive spaces
    if (preg_match("/^\s/", $what) || preg_match("/\s$/", $what) || preg_match("/\s\s/", $what)) {
        return false;
    }

    // Check the length of $what
    $l = strlen($what);
    if (!is_null($min) && $l < $min) {
        return false;
    }
    if (!is_null($max) && $l > $max) {
        return false;
    }

    return true;
}

function usage() {
    echo <<<END

usage:

 changepassword   --server <user>:<pass>@<host>:<port>
                  --newpassword <password>
                  [--cltrid <cltrid>]
                  [--logdir <directory>]
 Note: The Unix shell intercepts some special characters and tries to
       interpret them (f.e. \$). To pass a password string with special
       characters to the EPP toolkit please encode the password in the format
       \$'<password>'. If you want to use a single quote within the password
       string please escape it with a backslash (\\')

END;

    exit(-1);
}
