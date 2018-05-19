<?php 

function _encrypt($message, $hmac = FALSE)
{
	date_default_timezone_set('UTC');
	$secret = '474MaXCKBtASxDT6hgyU067THgqmnB==';
	$encryptionMethod = 'AES-256-CBC';
	$iv = substr(bin2hex(openssl_random_pseudo_bytes(16)),0,16);
	$encrypted = base64_encode($iv) . openssl_encrypt($message, $encryptionMethod, $secret, 0, $iv);

	return $encrypted;

}

function _decrypt($message, $hmac = FALSE)
{
	date_default_timezone_set('UTC');
	$secret = '474MaXCKBtASxDT6hgyU067THgqmnB==';
	$encryptionMethod = 'AES-256-CBC';
	$iv = base64_decode(substr($message, 0, 24));

	return openssl_decrypt(substr($message, 24), $encryptionMethod, $secret, 0, $iv);

}

$message = 'This is a test message.';
$encrypted_message = _encrypt($message);
$decrypted_message = _decrypt($encrypted_message);

echo 'Message: ' . $message . "\n";
echo 'Encrypted message: ' . $encrypted_message . "\n";
echo 'Derypted message: ' . $decrypted_message . "\n";