<?php declare(strict_types=1);

namespace OpenPGP\Tests\Packet;

use OpenPGP\Packet\PacketList;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for the time it takes to decode a packet list.
 */
class PacketListDecodeTimeTest extends OpenPGPTestCase
{
    public function testDecodeTimeGrowsLinearly()
    {
        $time = static function (int $packets): float {
            // Empty marker packets, two octets each.
            $bytes = str_repeat("\xca\x00", $packets);
            $start = hrtime(true);
            PacketList::decode($bytes);
            return (hrtime(true) - $start) / 1e9;
        };
        $time(1000);
        $small = $time(50000);
        $large = $time(200000);
        // Four times the input; linear time gives a factor of about 4.
        $this->assertLessThan(
            8.0,
            $large / $small,
            sprintf("%.3f s for 100 kB, %.3f s for 400 kB.", $small, $large)
        );
    }
}
