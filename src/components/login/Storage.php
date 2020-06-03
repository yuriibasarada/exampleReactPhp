<?php


namespace components\login;

use React\MySQL\ConnectionInterface;
use React\MySQL\QueryResult;
use React\Promise\PromiseInterface;
use components\login\errors\UserNotFound;

final class Storage
{
    /**
     * @var ConnectionInterface
     */
    private $connection;

    public function __construct(ConnectionInterface $connection)
    {
        $this->connection = $connection;
    }

    public function findByEmail(string $email): PromiseInterface
    {
        return $this->connection
            ->query(
                'SELECT id, email, password, name FROM user WHERE email = ?',
                [$email]
            )
            ->then(function (QueryResult $result) {
                if (empty($result->resultRows)) {
                    throw new UserNotFound();
                }

                $row = $result->resultRows[0];
                return new User(
                    (int)$row['id'],
                    $row['email'],
                    $row['password'],
                    $row['name']
                );
            });
    }
}