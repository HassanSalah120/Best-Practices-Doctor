<?php

namespace App\Services\Game;

final class GameServer
{
    public function __construct(
        private readonly GameServerQueueServiceInterface $queue,
        private readonly GameServerRedisCircuitBreaker $redisCircuitBreaker,
        private readonly GameSocketTokenServiceInterface $tokenService,
        private readonly GameSocketCommandServiceInterface $commandService,
        private readonly SessionVisibilityServiceInterface $sessionVisibility,
        private readonly GameServerEventHandler $eventHandler,
        private readonly GameServerConnectionManager $connectionManager,
    ) {
    }

    public function boot(): void
    {
        $this->queue->start();
        $this->eventHandler->broadcastSystemEvent('boot');
    }

    public function handleConnection(object $connection): void
    {
        $this->connectionManager->register($connection);
        $this->eventHandler->broadcastConnectionState($connection);
    }

    public function authenticate(object $connection, string $token): void
    {
        $identity = $this->tokenService->resolve($token);
        $this->connectionManager->attachIdentity($connection, $identity);
    }

    public function authorizeSession(object $connection, string $sessionId): void
    {
        $allowed = $this->sessionVisibility->canJoin($connection, $sessionId);
        $this->connectionManager->setVisibility($connection, $allowed);
    }

    public function handleCommand(object $connection, array $payload): void
    {
        $command = $this->commandService->parse($payload);
        $this->eventHandler->broadcastCommandState($connection, $command);
    }

    public function heartbeat(object $connection): void
    {
        $this->connectionManager->touch($connection);
    }

    public function close(object $connection): void
    {
        $this->connectionManager->forget($connection);
        $this->eventHandler->broadcastConnectionClosed($connection);
    }
}
