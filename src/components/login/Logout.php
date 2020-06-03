<?php


namespace components\login;


use core\JsonResponse;

class Logout
{
    public function __invoke() {
        return JsonResponse::ok([]);
    }
}