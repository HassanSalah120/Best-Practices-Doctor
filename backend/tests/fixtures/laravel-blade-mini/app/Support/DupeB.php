<?php

namespace App\Support;

class DupeB
{
    public function bigBlock(array $items): int
    {
        $sum = 0;
        foreach ($items as $i) {
            if ($i % 2 === 0) {
                $sum += $i;
            } else {
                $sum += ($i * 2);
            }
            if ($sum > 1000) {
                $sum -= 100;
            }
        }

        // Inflate token count to reliably trigger dry-violation
        $a = 1;
        $b = 2;
        $c = 3;
        $d = 4;
        $e = 5;
        if ($a < $b && $c < $d) {
            $sum += $a + $b + $c + $d + $e;
        } else {
            $sum += ($a * $b) + ($c * $d) + ($e * 10);
        }
        for ($j = 0; $j < 10; $j++) {
            $sum += $j;
            if ($j % 3 === 0) {
                $sum += 7;
            }
        }

        $sum = $sum + 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9 + 10;
        $sum = $sum + 11 + 12 + 13 + 14 + 15 + 16 + 17 + 18 + 19 + 20;
        return $sum;
    }
}
