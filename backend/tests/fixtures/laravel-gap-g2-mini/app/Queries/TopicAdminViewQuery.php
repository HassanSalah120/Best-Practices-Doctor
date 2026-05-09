<?php

namespace App\Queries;

class TopicAdminViewQuery
{
    public function showTopic(object $topic): array
    {
        return [
            'id' => $topic->id ?? null,
            'title' => $topic->title ?? null,
        ];
    }
}
