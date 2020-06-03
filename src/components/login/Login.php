<?php


namespace components\login;

use components\login\errors\BadCredentials;
use components\login\errors\UserNotFound;
use core\JsonResponse;
use Exception;
use Psr\Http\Message\ServerRequestInterface;

class Login
{

    private $authentication;

    public function __construct(Authentication $authentication)
    {
        $this->authentication = $authentication;
    }

    public function __invoke(ServerRequestInterface $request)
    {
        $input = new Input($request);
        $input->validate();
        return $this->authentication->authenticate($input->email(), $input->password())
            ->then(function (string $jwt) {
                return JsonResponse::ok(['token' => $jwt]);
            })
            ->otherwise(
                function (BadCredentials $exception) {
                    return JsonResponse::unauthorised('Bad Credentials');
                }
            )
            ->otherwise(
                function (UserNotFound $exception) {
                    return JsonResponse::unauthorised('User not found');
                }
            )
            ->otherwise(
                function (Exception $exception) {
                    return JsonResponse::internalServerError($exception->getMessage());
                }
            );


    }
}