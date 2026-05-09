{{-- Positive: query in Blade (should be moved to controller) --}}
@foreach(\App\Models\User::all() as $user)
    <div>{{ $user->name }}</div>
@endforeach

