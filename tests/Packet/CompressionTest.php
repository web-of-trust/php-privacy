<?php declare(strict_types=1);

namespace OpenPGP\Tests\Packet;

use OpenPGP\Enum\CompressionAlgorithm;
use OpenPGP\Packet\CompressedData;
use OpenPGP\Packet\LiteralData;
use OpenPGP\Packet\PacketList;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for compression packet.
 */
class CompressionTest extends OpenPGPTestCase
{
    public function testZip()
    {
        $literalData = LiteralData::fromText($this->faker->sentence(100));
        $packets = new PacketList([$literalData]);
        $compressed = CompressedData::fromPacketList(
            $packets, CompressionAlgorithm::Zip
        );
        $this->assertSame($packets, $compressed->getPackets());

        $decompressed = CompressedData::fromBytes($compressed->toBytes());
        $this->assertSame(CompressionAlgorithm::Zip, $decompressed->getAlgorithm());
        $this->assertEquals($packets, $decompressed->getPackets());
    }

    public function testZlib()
    {
        $literalData = LiteralData::fromText($this->faker->sentence(100));
        $packets = new PacketList([$literalData]);
        $compressed = CompressedData::fromPacketList(
            $packets, CompressionAlgorithm::Zlib
        );
        $this->assertSame($packets, $compressed->getPackets());

        $decompressed = CompressedData::fromBytes($compressed->toBytes());
        $this->assertSame(CompressionAlgorithm::Zlib, $decompressed->getAlgorithm());
        $this->assertEquals($packets, $decompressed->getPackets());
    }

    public function testBZip2()
    {
        $literalData = LiteralData::fromText($this->faker->sentence(100));
        $packets = new PacketList([$literalData]);
        $compressed = CompressedData::fromPacketList(
            $packets, CompressionAlgorithm::BZip2
        );
        $this->assertSame($packets, $compressed->getPackets());

        $decompressed = CompressedData::fromBytes($compressed->toBytes());
        $this->assertSame(CompressionAlgorithm::BZip2, $decompressed->getAlgorithm());
        $this->assertEquals($packets, $decompressed->getPackets());
    }
}
