<?php

namespace App\Services\Realtime;

use App\Actions\Realtime\DispatchPresenceSnapshotAction;
use App\Contracts\Realtime\QueueDriverInterface;

final class RealtimeWorkflowCoordinator
{
    public function __construct(
        private readonly QueueDriverInterface $queueDriver,
        private readonly ConnectionGateway $connections,
        private readonly SessionVisibilityService $visibility,
        private readonly TokenIssuer $tokenIssuer,
        private readonly CommandDispatcher $commands,
        private readonly PresencePublisher $presencePublisher,
        private readonly MetricsStore $metricsStore,
        private readonly DispatchPresenceSnapshotAction $snapshot,
    ) {
    }

    public function boot(string $sessionId): void
    {
        $this->visibility->open($sessionId);
        $this->snapshot->execute($sessionId);
    }

    public function syncConnections(string $sessionId): void
    {
        $payload = $this->connections->listForSession($sessionId);
        $this->presencePublisher->publish($sessionId, $payload);
    }

    public function dispatchCommand(string $sessionId, array $payload): void
    {
        $this->commands->dispatch($sessionId, $payload);
        $this->metricsStore->increment('commands.dispatched');
    }

    public function rotateToken(string $sessionId): string
    {
        return $this->tokenIssuer->issue($sessionId);
    }

    public function flushQueue(string $sessionId): void
    {
        $this->queueDriver->push($sessionId, ['type' => 'flush']);
    }
}
