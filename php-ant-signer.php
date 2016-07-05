#!/usr/bin/env php
<?php

namespace PHPAnt\Core;

include('includes/PHPAntSigner.class.php');
include('includes/PHPAntSignerFile.class.php');

function help() {
?>

SUMMARY:
Creates and signs manifest files, keys, and other resources needed to publish
an app for the PHP-Ant framework.

USAGE:
php-ant-signer [options] [/path/to/private/key]

  -a [app name]             REQUIRED. The app name you're signing. (the directory
                            name as it appears under include/apps/)
  -g                        Generates a new public and private key pair.
  -s [/path/to/private/key] Generates a manfest file and signs it with your private key.
  -v                        Verifies an app's manifest file, and the files listed
                            in it to ensure their authenticity.

IMPORTANT

When generating your keys, be sure to MOVE your private key out of the app
directory. The script will not allow you to sign your app unless it has been
moved out of the app directory; however, BE SURE to save this key in a safe
place! And, rename it to something other than private.key. Something like you-
app-name-private.key is better.

If you lose your private key, you will not be able to change your code, and
updates to your app may break.

<?php
exit();
}

$shortopts = "a:g::h::s::v::"; 
$longopts = [];
/*$longopts  = ['app'
             ,'generate-keys'
             ,'help'
             ,'sign-app'
             ,'verify-app'
             ];*/

$opts = getopt($shortopts,$longopts);
if(count($opts) === 0) help();

if(!array_key_exists('a', $opts) && !array_key_exists('g', $opts)) help();

$Signer = new PHPAntSigner();
$Signer->setApp($opts['a']);

if(array_key_exists('g', $opts)) $Signer->genKeys(true);
if(array_key_exists('s', $opts)) $Signer->signApp($opts['s']);
if(array_key_exists('v', $opts)) echo ($Signer->verifyApp()?PHP_EOL . "App integrity OK" . PHP_EOL: PHP_EOL . "App integrity could NOT be verified! Reinstall from the vendor!" . PHP_EOL);