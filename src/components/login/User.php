<?php


namespace components\login;


final class User
{

    public $id;

    public $email;

    public $password;

    public $name;

    public function __construct(int $id, string $email, string $password, string $name)
    {
        $this->id = $id;
        $this->email = $email;
        $this->password = $password;
        $this->name = $name;
    }
}