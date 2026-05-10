<?php

namespace App\Http\Controllers;

use App\Models\Post;
use App\Services\SlugService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

class PostController
{
    public function __construct(
        private readonly SlugService $slugs,
    ) {
    }

    public function storeDraft(Request $request): RedirectResponse
    {
        $title = (string) $request->input('title', '');
        $slug = $this->slugs->make($title);

        Post::query()->create([
            'title' => $title,
            'slug' => $slug,
        ]);

        return redirect()->back()->with('status', 'drafted');
    }
}
