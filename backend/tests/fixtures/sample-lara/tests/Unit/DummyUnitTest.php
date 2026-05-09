<?php

use PHPUnit\Framework\TestCase;

final class DummyUnitTest extends TestCase
{
    public function test_dummy_unit(): void
    {
        $this->assertNotEmpty("ok");
    }
}

