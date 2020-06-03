<?php

use Authenticator\Authentication;
use Authenticator\Guard;
use Authenticator\SignInController;
use Core\ErrorHandler;
use Core\JsonRequestDecoder;
use Core\Router;
use Dotenv\Dotenv;
use FastRoute\DataGenerator\GroupCountBased;
use FastRoute\RouteCollector;
use FastRoute\RouteParser\Std;
use React\EventLoop\Factory;
use React\Http\Server;
use React\MySQL\Factory as FactorySQL;
use Sikei\React\Http\Middleware\CorsMiddleware;
use Authenticator\Storage as User;

require_once 'vendor/autoload.php';

$env = Dotenv::create(__DIR__);
$env->load();

$loop = Factory::create();

$mysql = new FactorySQL($loop);
$uri = getenv('DB_LOGIN') . ':' . getenv('DB_PASS') . '@' . getenv('DB_HOST') . '/' . getenv('DB_NAME');
$connection = $mysql->createLazyConnection($uri);

$guard = new Guard(getenv('JWT_KEY'));

$user = new User($connection);
$authenticator = new Authentication($user, getenv('JWT_KEY'));

$routes = new RouteCollector(new Std(), new GroupCountBased());
$routes->post('/login', new SignInController($authenticator));

$settings = [
    'allow_origin'      => ['*'],
    'allow_headers'     => ['DNT','X-Custom-Header','Keep-Alive','User-Agent','X-Requested-With','If-Modified-Since','Cache-Control','Content-Type','Content-Range','Range'],
    'allow_methods'     => ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'],
];
$middleware = [new CorsMiddleware($settings), new ErrorHandler(), new JsonRequestDecoder(), new Router($routes)];
$server = new Server($middleware);
$socket = new \React\Socket\Server('127.0.0.1:8000', $loop);

$server->listen($socket);

$server->on('error', function (Throwable $error) {
    echo 'Error: ' . $error->getMessage() . PHP_EOL;
});

echo 'Listening on ' . str_replace('tcp', 'http', $socket->getAddress()) . PHP_EOL;

$loop->run();