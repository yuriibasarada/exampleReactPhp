<?php declare(strict_types=1);


namespace core;


use React\Http\Response;

final class JsonResponse extends Response
{
    public function __construct(int $statusCode, $data = null)
    {
        $data = $data ? json_encode($data) : null;

        parent::__construct(
            $statusCode,
            ['Content-type' => 'application/json'],
            $data
        );
    }

    public static function ok(array $data): self
    {
        return new self(200, $data);
    }

    public static function internalServerError(string $reason): self
    {
        return new self(500, ['message' => $reason]);
    }

    public static function badRequest(string ...$error): self
    {
        return new self(400, ['errors' => $error]);
    }

    public static function unauthorised(string $error = 'Error')
    {
        return new self(401, ['error' => $error]);
    }
}