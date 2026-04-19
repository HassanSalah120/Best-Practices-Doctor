<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Inertia\Inertia;
use Inertia\Response;

class ActivityLogController extends Controller
{
    public function index(Request $request): Response
    {
        $search = $request->string('q')->trim()->value();
        $action = $request->string('action')->value() ?: 'all';
        $actor = $request->string('actor')->value() ?: 'all';

        return Inertia::render('Admin/ActivityLogs', [
            'filters' => [
                'q' => $search,
                'action' => $action,
                'actor' => $actor,
            ],
        ]);
    }
}
