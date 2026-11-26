<?php declare(strict_types=1);

namespace OpenPGP\Tests\Packet;

use OpenPGP\Common\Config;
use OpenPGP\Enum\CompressionAlgorithm;
use OpenPGP\Packet\{CompressedData, LiteralData, PacketList};
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for rejecting compression algorithms.
 */
class RejectedCompressionTest extends OpenPGPTestCase
{
    private static function compressed(CompressionAlgorithm $algorithm): string
    {
        return CompressedData::fromPacketList(
            new PacketList([LiteralData::fromText("Hello")]),
            $algorithm
        )->toBytes();
    }

    public function testRejectedCompressionIsNotRead()
    {
        if (!\function_exists("bzcompress")) {
            $this->markTestSkipped("The bz2 extension is not loaded.");
        }
        $bzip2 = self::compressed(CompressionAlgorithm::BZip2);
        $zip = self::compressed(CompressionAlgorithm::Zip);

        // By default every algorithm is read.
        $this->assertSame([], Config::getRejectedCompressions());
        $this->assertInstanceOf(
            CompressedData::class,
            CompressedData::fromBytes($bzip2)
        );

        Config::setRejectedCompressions([CompressionAlgorithm::BZip2]);
        try {
            $error = "";
            try {
                CompressedData::fromBytes($bzip2);
            } catch (\RuntimeException $e) {
                $error = $e->getMessage();
            }
            $other = CompressedData::fromBytes($zip);
        } finally {
            Config::setRejectedCompressions([]);
        }
        $this->assertSame("Compression algorithm BZip2 is rejected.", $error);
        $this->assertInstanceOf(CompressedData::class, $other);
    }

    public function testRejectedCompressionsMustBeAlgorithms()
    {
        $this->expectException(\InvalidArgumentException::class);
        Config::setRejectedCompressions(["BZip2"]);
    }
}
