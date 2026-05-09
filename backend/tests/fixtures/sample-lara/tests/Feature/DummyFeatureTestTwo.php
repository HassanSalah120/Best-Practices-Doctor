<?php

use PHPUnit\Framework\TestCase;

final class DummyFeatureTestTwo extends TestCase
{
    public function test_dummy_feature_two(): void
    {
        $this->assertSame(1, 1);
    }
}

