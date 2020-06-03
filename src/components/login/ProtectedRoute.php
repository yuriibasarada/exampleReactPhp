<?php declare(strict_types=1);

namespace components\login;

use core\JsonResponse;
use Firebase\JWT\JWT;
use RingCentral\Psr7\ServerRequest;

final class ProtectedRoute
{

    private $jwtKey;

    private $middleware;

    public function __construct(string $jwtKey, callable $middleware)
    {
        $this->jwtKey = $jwtKey;
        $this->middleware = $middleware;
    }

    public function __invoke(ServerRequest $request)
    {
        if($this->authorize($request)) {
            return call_user_func($this->middleware, $request);
        }
        return JsonResponse::unauthorised();
    }

    private function authorize(ServerRequest $request)
    {
        $header = $request->getHeaderLine('Authorization');
        $token = str_replace('Bearer', '', $header);
        if(empty($token)) {
            return false;
        }

        return JWT::decode($token, $token->jwtKey, ['HS256']) !== null;
    }


}