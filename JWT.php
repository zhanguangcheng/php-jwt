<?php

use DateTime;
use DomainException;
use UnexpectedValueException;

/**
 * JSON Web Token implementation
 *
 * Minimum implementation used by Realtime auth, based on this spec:
 * http://self-issued.info/docs/draft-jones-json-web-token-01.html.
 *
 * @author Neuman Vong <neuman@twilio.com>
 */
class JWT
{
    /**
     * @param object|array $payload PHP object or array
     * [
     *  'iss'=>'admin',  //签发者
     *  'iat'=>time(),  //签发时间 issued at date
     *  'exp'=>time()+7200,  //过期时间 expiration date
     *  'nbf'=>time()+60,  //该时间之前不接收处理该Token not before date
     * ]
     * @param string       $key     The secret key
     * @param string       $algo    The signing algorithm
     *
     * @return string A JWT
     */
    public static function encode($payload, $key, $algo = 'HS256')
    {
        $header = array('typ' => 'JWT', 'alg' => $algo);

        $segments = array();
        $segments[] = JWT::urlsafeB64Encode(JWT::jsonEncode($header));
        $segments[] = JWT::urlsafeB64Encode(JWT::jsonEncode($payload));
        $signing_input = implode('.', $segments);

        $signature = JWT::sign($signing_input, $key, $algo);
        $segments[] = JWT::urlsafeB64Encode($signature);

        return implode('.', $segments);
    }

    /**
     * @param string      $jwt    The JWT
     * @param string|null $key    The secret key
     * @param bool $verify 是否验证
     *
     * @return array The JWT's payload as a PHP array
     */
    public static function decode($jwt, $key = null, $verify = true)
    {
        $tks = explode('.', $jwt);
        if (count($tks) != 3) {
            throw new UnexpectedValueException('Wrong number of segments', 1);
        }
        list($headb64, $payloadb64, $cryptob64) = $tks;
        if (null === ($header = JWT::jsonDecode(JWT::urlsafeB64Decode($headb64)))) {
            throw new UnexpectedValueException('Invalid segment encoding', 1);
        }
        if (null === ($payload = JWT::jsonDecode(JWT::urlsafeB64Decode($payloadb64)))) {
            throw new UnexpectedValueException('Invalid segment encoding', 1);
        }
        if (empty($header['alg'])) {
            throw new DomainException('Empty algorithm', 1);
        }
        $sig = JWT::urlsafeB64Decode($cryptob64);
        if ($sig != JWT::sign("$headb64.$payloadb64", $key, $header['alg'])) {
            throw new UnexpectedValueException('Signature verification failed', 2);
        }
        if ($verify) {
            // 签发时间大于当前服务器时间验证失败
            if (isset($payload['iat']) && $payload['iat'] > time()) {
                throw new UnexpectedValueException('Token iat is not valid before: ' . date(DateTime::ISO8601, $payload['iat']), 3);
            }
            // 过期时间小宇当前服务器时间验证失败
            if (isset($payload['exp']) && $payload['exp'] < time()) {
                throw new UnexpectedValueException('Token exp is not valid since: ' . date(DateTime::ISO8601, $payload['exp']), 4);
            }
            // 该nbf时间之前不接收处理该Token
            if (isset($payload['nbf']) && $payload['nbf'] > time()) {
                throw new UnexpectedValueException('Token nbf is not valid before: ' . date(DateTime::ISO8601, $payload['nbf']), 5);
            }
        }
        return $payload;
    }

    /**
     * @param string $msg    The message to sign
     * @param string $key    The secret key
     * @param string $method The signing algorithm
     *
     * @return string An encrypted message
     */
    public static function sign($msg, $key, $method = 'HS256')
    {
        $methods = array(
            'HS256' => 'sha256',
            'HS384' => 'sha384',
            'HS512' => 'sha512',
        );
        if (empty($methods[$method])) {
            throw new DomainException('Algorithm not supported');
        }
        return hash_hmac($methods[$method], $msg, $key, true);
    }

    /**
     * @param string $input JSON string
     *
     * @return object Object representation of JSON string
     */
    public static function jsonDecode($input)
    {
        $obj = json_decode($input, true);
        if (function_exists('json_last_error') && $errno = json_last_error()) {
            JWT::handleJsonError($errno);
        } else if ($obj === null && $input !== 'null') {
            throw new DomainException('Null result with non-null input');
        }
        return $obj;
    }

    /**
     * @param object|array $input A PHP object or array
     *
     * @return string JSON representation of the PHP object or array
     */
    public static function jsonEncode($input)
    {
        $json = json_encode($input, JSON_UNESCAPED_UNICODE);
        if (function_exists('json_last_error') && $errno = json_last_error()) {
            JWT::handleJsonError($errno);
        } else if ($json === 'null' && $input !== null) {
            throw new DomainException('Null result with non-null input');
        }
        return $json;
    }

    /**
     * @param string $input A base64 encoded string
     *
     * @return string A decoded string
     */
    public static function urlsafeB64Decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * @param string $input Anything really
     *
     * @return string The base64 encode of what you passed in
     */
    public static function urlsafeB64Encode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * @param int $errno An error number from json_last_error()
     *
     * @return void
     */
    private static function handleJsonError($errno)
    {
        $messages = array(
            JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON'
        );
        throw new DomainException(
            isset($messages[$errno])
                ? $messages[$errno]
                : 'Unknown JSON error: ' . $errno
        );
    }
}
