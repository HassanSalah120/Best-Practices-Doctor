<?php

// Negative: env() usage is allowed in config files.
return [
    "stripe" => [
        "key" => env("STRIPE_KEY", ""),
    ],
];

