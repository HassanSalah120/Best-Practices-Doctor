<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Queries\TopicAdminViewQuery;
use Illuminate\Http\Request;
use Inertia\Inertia;
use Inertia\Response;

class DelegatedTopicViewController extends Controller
{
    public function __construct(
        private readonly TopicAdminViewQuery $topicAdminViewQuery,
    ) {
    }

    public function show(Request $request, object $topic): Response
    {
        return Inertia::render('Admin/TopicShow', [
            'topic' => $this->topicAdminViewQuery->showTopic($topic),
        ]);
    }
}
