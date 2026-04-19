<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Inertia\Inertia;
use Inertia\Response;

class SubmissionManagementController extends Controller
{
    public function index(Request $request): Response
    {
        $status = $request->string('status')->value() ?: 'all';
        $search = $request->string('q')->trim()->value();

        return Inertia::render('Admin/Submissions', [
            'filters' => [
                'status' => $status,
                'q' => $search,
            ],
        ]);
    }

    public function show(Request $request, object $submission): Response
    {
        return Inertia::render('Admin/SubmissionShow', [
            'submission' => [
                'id' => $submission->id ?? null,
                'status' => $submission->status ?? 'draft',
                'topic' => [
                    'id' => $submission->topic->id ?? null,
                    'title' => $submission->topic->title ?? null,
                    'status' => $submission->topic->status ?? null,
                    'created_at' => $submission->topic->created_at ?? null,
                    'updated_at' => $submission->topic->updated_at ?? null,
                ],
                'items' => collect($submission->items ?? [])
                    ->sortBy('rank')
                    ->values()
                    ->map(fn ($item) => [
                        'rank' => $item->rank ?? null,
                        'label' => $item->label ?? null,
                        'score' => $item->score ?? null,
                        'delta' => $item->delta ?? null,
                    ]),
            ],
        ]);
    }
}
