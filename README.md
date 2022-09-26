# php-jwt

## 生成JWT
```php
require './JWT.php';
$key = 'sign key';
$jwt = JWT::encode([
    'iss' => 'https://api.example.com',
    'iat' => time(),
    'exp' => time() + 3600,
    'uid' => 1,
    'name' => 'Grass'
], $key);
echo "jwt encode:$jwt\n\n";
```

## JWT解码
```php
require './JWT.php';
$key = 'sign key';
try {
    $payload = JWT::decode($jwt, $key);
    echo "jwt decode:";
    print_r($payload);
} catch(Excpetion $e) {
    var_dump("decode error:" . $e->getMessage() . '(' . $e->getCode() . ')');
}
```

输出结果
```
jwt encode:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvYXBpLmV4YW1wbGUuY29tIiwiaWF0IjoxNjY0MjA1MjY4LCJleHAiOjE2NjQyMDg4NjgsInVpZCI6MSwibmFtZSI6IkdyYXNzIn0.wzxVphPKeAdReejkfRWZ7CrZscAQB9fqqtz46NLH97Y

jwt decode:Array
(
    [iss] => https://api.example.com
    [iat] => 1664205268
    [exp] => 1664208868
    [uid] => 1
    [name] => Grass
)
```