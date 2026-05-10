<?php

namespace App\Http\Controllers;

use App\Models\Post;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

class PostController
{
    public function publish(Request $request): RedirectResponse
    {
        $items = (array) $request->input('items', []);
        $authorId = (int) $request->input('author_id', 0);
        $shouldNotify = $request->boolean('notify_author');
        $score = $this->calculatePublishScore($items);

        if ($score > 100) {
            Post::query()->where('status', 'draft')->update(['status' => 'scheduled']);
        } else {
            Post::query()->where('status', 'draft')->update(['status' => 'review']);
        }

        if ($shouldNotify && $authorId > 0) {
            Post::query()->whereKey($authorId)->update(['last_published_score' => $score]);
        }

        return redirect()->back()->with('status', (string) $score);
    }

    private function calculatePublishScore(array $items): int
    {
        $score = 0;

        foreach ($items as $item) {
            $value = (int) ($item['value'] ?? 0);

            if ($value > 10) {
                $score += $value * 2;
            } else {
                $score += $value;
            }
        }

        return $score;
    }
}
