<?php


namespace components\login;

use components\login\errors\BadCredentials;
use Firebase\JWT\JWT;
use React\Promise\PromiseInterface;

final class Authentication
{
    private const TOKEN_EXPIRES_IN = 60 * 60;

    private $storage;

    private $jwtKey;

    public function __construct(Storage $storage, string $jwtKey)
    {
        $this->storage = $storage;
        $this->jwtKey = $jwtKey;
    }

    public function authenticate(string $email, string $password): PromiseInterface
    {

        return $this->storage->findByEmail($email)
            ->then(function (User $user) use ($password){
                if(!password_verify($password, $user->password)) {
                    return new BadCredentials();
                }
                $payload = [
                    'id' => $user->id,
                    'email' => $user->email,
                    'exp' => time() + self::TOKEN_EXPIRES_IN
                ];
                return JWT::encode($payload, $this->jwtKey);
            });
    }
}