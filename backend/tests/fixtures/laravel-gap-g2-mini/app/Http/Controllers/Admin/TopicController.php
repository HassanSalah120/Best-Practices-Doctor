<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Inertia\Inertia;
use Inertia\Response;

class TopicController extends Controller
{
    public function show(Request $request, object $topic): Response
    {
        return Inertia::render('Admin/TopicShow', [
            'topic' => $this->buildTopicViewData($topic),
            'options' => $this->formatTopicOptions($topic),
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private function buildTopicViewData(object $topic): array
    {
        return [
            ...$this->serializeTopicForView($topic),
            'options_count' => count($topic->options ?? []),
            'submissions_count' => $topic->submissions_count ?? 0,
            'submitted_count' => $topic->submitted_count ?? 0,
        ];
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function formatTopicOptions(object $topic): array
    {
        return collect($topic->options ?? [])
            ->sortBy('display_order')
            ->values()
            ->map(fn ($option) => [
                'display_order' => $option->display_order ?? null,
                'label' => $option->label ?? null,
                'score' => $option->score ?? null,
            ])
            ->all();
    }

    /**
     * @return array<string, mixed>
     */
    private function serializeTopicForView(object $topic): array
    {
        return [
            'public_id' => $topic->public_id ?? null,
            'title' => $topic->title ?? null,
            'description' => $topic->description ?? null,
            'status' => $topic->status ?? 'draft',
            'published_at' => $topic->published_at ?? null,
            'closed_at' => $topic->closed_at ?? null,
        ];
    }
}
