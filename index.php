<?php
//https://stackoverflow.com/questions/10916284/how-to-encrypt-decrypt-data-in-php


//http://php.net/manual/en/function.openssl-encrypt.php
//encrypt (client end)
$auth_token = md5(microtime());
$plaintext = "whyibudget.".$auth_token;//domain . auth_token
echo $plaintext."\n";
$key = openssl_random_pseudo_bytes(32, $strong);

$cipher="AES-128-CBC";
$ivlen = openssl_cipher_iv_length($cipher);
$iv = openssl_random_pseudo_bytes($ivlen);
$ciphertext_raw = openssl_encrypt($plaintext, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
$hmac = hash_hmac('sha256', $ciphertext_raw, $key, true);
$ciphertext = base64_encode($iv.$hmac.$ciphertext_raw);


//decrypt (my end)
$c = base64_decode($ciphertext);
$ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
$iv = substr($c, 0, $ivlen);
$hmac = substr($c, $ivlen, $sha2len=32);
$ciphertext_raw = substr($c, $ivlen+$sha2len);
$calcmac = hash_hmac('sha256', $ciphertext_raw, $key, true);

if(hash_equals($hmac, $calcmac)) {
    $original_plaintext = openssl_decrypt($ciphertext_raw, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
    echo $original_plaintext."\n";
}