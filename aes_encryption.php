<?php 

function _encrypt($message, $hmac = FALSE)
{
	date_default_timezone_set('UTC');
	$secret 									= 'T6h474MagTHgXCKBtASxDqmnB==yU067';
	$encryptionMethod 							= 'AES-256-CBC';
	$iv 										= substr(bin2hex(openssl_random_pseudo_bytes(16)),0,16);
	$encrypted 									= base64_encode($iv) . openssl_encrypt($message, $encryptionMethod, $secret, 0, $iv);

	return $encrypted;
	
}

function _decrypt($message, $hmac = FALSE)
{
	date_default_timezone_set('UTC');
	$secret 									= 'T6h474MagTHgXCKBtASxDqmnB==yU067';
	$encryptionMethod 							= 'AES-256-CBC';
	$iv 										= base64_decode(substr($message, 0, 24));

	return openssl_decrypt(substr($message, 24), $encryptionMethod, $secret, 0, $iv);

}