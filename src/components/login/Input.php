<?php


namespace components\login;


use Psr\Http\Message\ServerRequestInterface;
use Respect\Validation\Validator;

class Input
{
    /**
     * @var ServerRequestInterface
     */
    private $request;

    public function __construct(ServerRequestInterface $request)
    {
        $this->request = $request;
    }

    public function validate(): void
    {
        $emailValidator = Validator::key('email',
            Validator::allOf(
                Validator::email(),
                Validator::notBlank(),
                Validator::stringType()
            ))->setName('email');
        $passwordValidator = Validator::key('password',
            Validator::allOf(
                Validator::notBlank(),
                Validator::stringType()
            ))->setName('password');
        $validator = Validator::allOf($emailValidator, $passwordValidator);

        $validator->assert($this->request->getParsedBody());
    }

    public function hashedPassword(): string
    {
        return password_hash($this->password(),PASSWORD_BCRYPT);
    }

    public function email(): string
    {
        return  $this->request->getParsedBody()['email'];
    }

    public function password(): string
    {
        return $this->request->getParsedBody()['password'];
    }
}