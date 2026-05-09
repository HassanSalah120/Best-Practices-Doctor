{{-- Negative: no query in Blade --}}
<div>{{ $user->name }}</div>

{{-- Positive: request-derived raw echo (blade-xss-risk) --}}
<div>{!! request('q') !!}</div>
