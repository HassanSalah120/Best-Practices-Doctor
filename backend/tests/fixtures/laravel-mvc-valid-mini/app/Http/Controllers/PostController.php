<?php

namespace App\Http\Controllers;

use App\Models\Post;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;

class PostController
{
    public function index(): View
    {
        $posts = Post::query()->latest()->take(10)->get();

        return view('posts.index', compact('posts'));
    }

    public function store(Request $request): RedirectResponse
    {
        Post::query()->create($request->only('title'));

        return redirect()->route('posts.index');
    }
}
