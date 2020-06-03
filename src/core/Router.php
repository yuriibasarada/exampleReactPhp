<?php declare(strict_types=1);


namespace core;


use FastRoute\Dispatcher\GroupCountBased;
use FastRoute\RouteCollector;
use Psr\Http\Message\ServerRequestInterface;
use React\Http\Response;

final class Router
{
    private $dispatcher;

    public function __construct(RouteCollector $routes)
    {
        $this->dispatcher = new GroupCountBased($routes->getData());
    }

    public function __invoke(ServerRequestInterface $request)
    {
        $routeInfo = $this->dispatcher->dispatch(
            $request->getMethod(), $request->getUri()->getPath()
        );

        switch ($routeInfo[0]) {
            case \FastRoute\Dispatcher::NOT_FOUND:
                return new Response(404, ['Content-Type' => 'plain/text'], 'Not found');
            case \FastRoute\Dispatcher::METHOD_NOT_ALLOWED:
                return new Response(405, ['Content-Type' => 'plain/text'], 'Method not allowed');
            case \FastRoute\Dispatcher::FOUND:
                $params = array_values($routeInfo[2]);
                return $routeInfo[1]($request, ...$params);
        }
    }
}