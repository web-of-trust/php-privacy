<?php declare(strict_types=1);

namespace OpenPGP\Tests\Packet;

use OpenPGP\Common\Config;
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
    const PASSPHRASE = "password";

    public function testZip()
    {
        $literalData = LiteralData::fromText($this->faker->sentence(10000));
        $packets = new PacketList([$literalData]);
        $compressed = CompressedData::fromPacketList(
            $packets,
            CompressionAlgorithm::Zip
        );
        $this->assertSame($packets, $compressed->getPacketList());

        $decompressed = CompressedData::fromBytes($compressed->toBytes());
        $this->assertSame(
            CompressionAlgorithm::Zip,
            $decompressed->getAlgorithm()
        );
        $this->assertEquals($packets, $decompressed->getPacketList());
    }

    public function testZlib()
    {
        $literalData = LiteralData::fromText($this->faker->sentence(10000));
        $packets = new PacketList([$literalData]);
        $compressed = CompressedData::fromPacketList(
            $packets,
            CompressionAlgorithm::Zlib
        );
        $this->assertSame($packets, $compressed->getPacketList());

        $decompressed = CompressedData::fromBytes($compressed->toBytes());
        $this->assertSame(
            CompressionAlgorithm::Zlib,
            $decompressed->getAlgorithm()
        );
        $this->assertEquals($packets, $decompressed->getPacketList());
    }

    public function testBZip2()
    {
        $literalData = LiteralData::fromText($this->faker->sentence(10000));
        $packets = new PacketList([$literalData]);
        $compressed = CompressedData::fromPacketList(
            $packets,
            CompressionAlgorithm::BZip2
        );
        $this->assertSame($packets, $compressed->getPacketList());

        $decompressed = CompressedData::fromBytes($compressed->toBytes());
        $this->assertSame(
            CompressionAlgorithm::BZip2,
            $decompressed->getAlgorithm()
        );
        $this->assertEquals($packets, $decompressed->getPacketList());
    }

    public function testZipDecompress()
    {
        $data = <<<EOT
jA0ECQMCRq12Ney7cav/0kIBVtvCp7e/6bftnl80wIN/ocPyTIoNgZUzAucL8Yxa
bZ7L0eBy4u8hgAVtrJCtETOLYeFMS51S/7ErdqyksWx9osw=
EOT;

        $packets = PacketList::decode(base64_decode($data));
        $skesk = $packets->offsetGet(0)->decrypt(self::PASSPHRASE);
        $sessionKey = $skesk->getSessionKey();
        $seip = $packets
            ->offsetGet(1)
            ->decrypt(
                $sessionKey->getEncryptionKey(),
                $sessionKey->getSymmetric()
            );

        $compressed = $seip->getPacketList()->offsetGet(0);
        $this->assertSame(
            CompressionAlgorithm::Zip,
            $compressed->getAlgorithm()
        );
        $literalData = $compressed->getPacketList()->offsetGet(0);
        $this->assertSame("Hello PHP PG\n", $literalData->getData());
    }

    public function testZlibDecompress()
    {
        $data = <<<EOT
jA0ECQMCLRbDkykeeZn/0kgBj3MScClX8/qZbP/HHT1XMXe8oc0FRSN8u6p+JbeC
cBZXWFgKE6GfHoK+8dlqnQYyPb9Xgh4MtFkw3OSFG9oO10Ggjuupq5Q=
EOT;

        $packets = PacketList::decode(base64_decode($data));
        $skesk = $packets->offsetGet(0)->decrypt(self::PASSPHRASE);
        $sessionKey = $skesk->getSessionKey();
        $seip = $packets
            ->offsetGet(1)
            ->decrypt(
                $sessionKey->getEncryptionKey(),
                $sessionKey->getSymmetric()
            );

        $compressed = $seip->getPacketList()->offsetGet(0);
        $this->assertSame(
            CompressionAlgorithm::Zlib,
            $compressed->getAlgorithm()
        );
        $literalData = $compressed->getPacketList()->offsetGet(0);
        $this->assertSame("Hello PHP PG\n", $literalData->getData());
    }

    public function testBZip2Decompress()
    {
        $data = <<<EOT
jA0ECQMCrf1YgAm7Evr/0m8BFPj2+nB5ipmTP0eWAAFxZCh4b7lTkE32a+nEABkg
kgYAl1ez6sJjNmyUYMzAWbfIEC0hoXioZKY6W/9KR7Ln0aK46/ZUGW3QKau7BwlY
64cgB5gvL4qH3TMmIaWMrJ+rr+zFD2RI+oakU2zAheg=
EOT;

        $packets = PacketList::decode(base64_decode($data));
        $skesk = $packets->offsetGet(0)->decrypt(self::PASSPHRASE);
        $sessionKey = $skesk->getSessionKey();
        $seip = $packets
            ->offsetGet(1)
            ->decrypt(
                $sessionKey->getEncryptionKey(),
                $sessionKey->getSymmetric()
            );

        $compressed = $seip->getPacketList()->offsetGet(0);
        $this->assertSame(
            CompressionAlgorithm::BZip2,
            $compressed->getAlgorithm()
        );
        $literalData = $compressed->getPacketList()->offsetGet(0);
        $this->assertSame("Hello PHP PG\n", $literalData->getData());
    }

    public function testDecompressionStopsAtSizeLimit()
    {
        $literalData = LiteralData::fromText(str_repeat("A", 1 << 20));
        $packets = new PacketList([$literalData]);
        $default = Config::getMaxDecompressedSize();
        foreach (
            [
                CompressionAlgorithm::Zip,
                CompressionAlgorithm::Zlib,
                CompressionAlgorithm::BZip2,
            ]
            as $algorithm
        ) {
            $bytes = CompressedData::fromPacketList(
                $packets,
                $algorithm
            )->toBytes();
            Config::setMaxDecompressedSize(1 << 19);
            $error = null;
            try {
                CompressedData::fromBytes($bytes);
            } catch (\RuntimeException $e) {
                $error = $e->getMessage();
            } finally {
                Config::setMaxDecompressedSize($default);
            }
            $this->assertNotNull(
                $error,
                "Decompression beyond the limit was accepted for " .
                    $algorithm->name . "."
            );
            $this->assertStringContainsString("exceeds the limit", $error);
            $decompressed = CompressedData::fromBytes($bytes);
            $this->assertEquals($packets, $decompressed->getPacketList());
        }
    }

    public function testDeeplyNestedCompressedDataIsRejected()
    {
        $packets = new PacketList([LiteralData::fromText("nested")]);
        // Eight levels are accepted, the ninth is not.
        for ($i = 0; $i < 8; $i++) {
            $packets = new PacketList([
                CompressedData::fromPacketList(
                    $packets,
                    CompressionAlgorithm::Zip
                ),
            ]);
        }
        $allowed = $packets->offsetGet(0)->toBytes();
        $decompressed = CompressedData::fromBytes($allowed);
        $this->assertInstanceOf(CompressedData::class, $decompressed);

        $tooDeep = CompressedData::fromPacketList(
            $packets,
            CompressionAlgorithm::Zip
        )->toBytes();
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("nested too deeply");
        CompressedData::fromBytes($tooDeep);
    }

    public function testCompressedDataPacketsSideBySideShareTheLimit()
    {
        $one = CompressedData::fromPacketList(
            new PacketList([LiteralData::fromText(str_repeat("A", 300000))]),
            CompressionAlgorithm::Zip
        )->encode();
        $default = Config::getMaxDecompressedSize();
        Config::setMaxDecompressedSize(1 << 20);
        try {
            // Three packets of about 300 KB fit into 1 MiB, four do not.
            $three = PacketList::decode(str_repeat($one, 3));
            $error = null;
            try {
                PacketList::decode(str_repeat($one, 4));
            } catch (\RuntimeException $e) {
                $error = $e->getMessage();
            }
        } finally {
            Config::setMaxDecompressedSize($default);
        }
        $this->assertCount(3, $three->getPackets());
        $this->assertNotNull(
            $error,
            "Compressed data packets side by side were each given the full limit."
        );
        $this->assertStringContainsString("exceeds the limit", $error);
    }

    public function testOneInflateStepStaysSmall()
    {
        if (!\function_exists("memory_reset_peak_usage")) {
            $this->markTestSkipped("memory_reset_peak_usage() needs PHP 8.2.");
        }
        $default = Config::getMaxDecompressedSize();
        foreach (
            [CompressionAlgorithm::Zip, CompressionAlgorithm::Zlib]
            as $algorithm
        ) {
            // 32 MiB of one octet compress by a factor of several hundred.
            $bytes = CompressedData::fromPacketList(
                new PacketList([
                    LiteralData::fromText(str_repeat("A", 32 << 20)),
                ]),
                $algorithm
            )->toBytes();
            \gc_collect_cycles();
            Config::setMaxDecompressedSize(1 << 20);
            \memory_reset_peak_usage();
            $before = \memory_get_usage();
            $error = null;
            try {
                CompressedData::fromBytes($bytes);
            } catch (\RuntimeException $e) {
                $error = $e->getMessage();
            } finally {
                Config::setMaxDecompressedSize($default);
            }
            $peak = \memory_get_peak_usage() - $before;
            $this->assertStringContainsString("exceeds the limit", $error);
            // The limit is 1 MiB; one step may add a little on top of it,
            // but not the whole compressed input expanded at once.
            $this->assertLessThan(
                8 << 20,
                $peak,
                "One decompression step produced " . $peak .
                    " octets for " . $algorithm->name . "."
            );
        }
    }

    public function testNestingLimitCanBeSet()
    {
        $packets = new PacketList([LiteralData::fromText("nested")]);
        for ($i = 0; $i < 2; $i++) {
            $packets = new PacketList([
                CompressedData::fromPacketList(
                    $packets,
                    CompressionAlgorithm::Zip
                ),
            ]);
        }
        $two = $packets->offsetGet(0)->toBytes();
        $three = CompressedData::fromPacketList(
            $packets,
            CompressionAlgorithm::Zip
        )->toBytes();
        $default = Config::getMaxCompressionNesting();
        Config::setMaxCompressionNesting(2);
        try {
            $decompressed = CompressedData::fromBytes($two);
            $error = null;
            try {
                CompressedData::fromBytes($three);
            } catch (\RuntimeException $e) {
                $error = $e->getMessage();
            }
        } finally {
            Config::setMaxCompressionNesting($default);
        }
        $this->assertInstanceOf(CompressedData::class, $decompressed);
        $this->assertNotNull($error, "Three levels were accepted with a limit of 2.");
        $this->assertStringContainsString("nested too deeply", $error);
        $this->assertInstanceOf(CompressedData::class, CompressedData::fromBytes($three));
    }

    public function testNestingLimitMustBePositive()
    {
        $this->expectException(\InvalidArgumentException::class);
        Config::setMaxCompressionNesting(0);
    }

    public function testDecompressionLimitMustBePositive()
    {
        $this->expectException(\InvalidArgumentException::class);
        Config::setMaxDecompressedSize(0);
    }
}
