<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Common\Config;
use OpenPGP\Enum\CompressionAlgorithm as Algorithm;
use OpenPGP\Enum\PacketTag;
use OpenPGP\Type\PacketListInterface;

/**
 * Implementation of the Compressed Data Packet (Tag 8)
 *
 * See RFC 9580, section 5.6.
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class CompressedData extends AbstractPacket
{
    /**
     * Default zip/zlib compression level, between 1 and 9
     */
    const DEFLATE_LEVEL = 6;

    /**
     * Largest number of compressed data packets nested in each other
     */
    const MAX_NESTING = 8;

    /**
     * Size of the parts that are decompressed at a time
     */
    const CHUNK_SIZE = 65536;

    /**
     * Nesting depth of the decompression running now, and the octets the
     * outermost packet list may still decompress
     */
    private static int $depth = 0;

    private static int $remaining = 0;

    /**
     * Constructor
     *
     * @param string $compressed
     * @param PacketListInterface $packetList
     * @param Algorithm $algorithm
     * @return self
     */
    public function __construct(
        private readonly string $compressed,
        private readonly PacketListInterface $packetList,
        private readonly Algorithm $algorithm = Algorithm::Uncompressed,
    ) {
        parent::__construct(PacketTag::CompressedData);
    }

    /**
     * {@inheritdoc}
     */
    public static function fromBytes(string $bytes): self
    {
        $algorithm = Algorithm::from(ord($bytes[0]));
        $compressed = substr($bytes, 1);
        return new self(
            $compressed,
            self::decompress($compressed, $algorithm),
            $algorithm,
        );
    }

    /**
     * Build compressed data packet from packet list
     *
     * @param PacketListInterface $packetList
     * @param Algorithm $algorithm
     * @return self
     */
    public static function fromPacketList(
        PacketListInterface $packetList,
        Algorithm $algorithm = Algorithm::Uncompressed,
    ): self {
        return new self(
            self::compress($packetList, $algorithm),
            $packetList,
            $algorithm,
        );
    }

    /**
     * Build compressed data packet from packet array
     *
     * @param array $packets
     * @param Algorithm $algorithm
     * @return self
     */
    public static function fromPackets(
        array $packets,
        Algorithm $algorithm = Algorithm::Uncompressed,
    ) {
        return self::fromPacketList(new PacketList($packets), $algorithm);
    }

    /**
     * Get compressed data
     *
     * @return string
     */
    public function getCompressed(): string
    {
        return $this->compressed;
    }

    /**
     * Get decompressed packet list contained within.
     *
     * @return PacketListInterface
     */
    public function getPacketList(): PacketListInterface
    {
        return $this->packetList;
    }

    /**
     * Get compression algorithm
     *
     * @return Algorithm
     */
    public function getAlgorithm(): Algorithm
    {
        return $this->algorithm;
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([chr($this->algorithm->value), $this->compressed]);
    }

    private static function compress(
        PacketListInterface $packetList,
        Algorithm $algorithm,
    ): string {
        return match ($algorithm) {
            Algorithm::Uncompressed => $packetList->encode(),
            Algorithm::Zip => \gzdeflate(
                $packetList->encode(),
                self::DEFLATE_LEVEL,
            ),
            Algorithm::Zlib => \gzcompress(
                $packetList->encode(),
                self::DEFLATE_LEVEL,
            ),
            Algorithm::BZip2 => \bzcompress($packetList->encode()),
        };
    }

    private static function decompress(
        string $compressed,
        Algorithm $algorithm,
    ): PacketListInterface {
        if (self::$depth >= self::MAX_NESTING) {
            throw new \RuntimeException(
                "Compressed data packets are nested too deeply.",
            );
        }
        if (!PacketList::isDecoding()) {
            self::startDecompression();
        }
        $data = match ($algorithm) {
            Algorithm::Uncompressed => self::take($compressed),
            Algorithm::Zip => self::inflate($compressed, ZLIB_ENCODING_RAW),
            Algorithm::Zlib => self::inflate($compressed, ZLIB_ENCODING_DEFLATE),
            Algorithm::BZip2 => self::bunzip($compressed),
        };
        self::$depth++;
        try {
            return PacketList::decode($data);
        } finally {
            self::$depth--;
        }
    }

    /**
     * Start counting decompressed octets against the limit. The outermost
     * packet list calls this once, so that all compressed data packets
     * in it, side by side or nested, share one limit.
     */
    public static function startDecompression(): void
    {
        self::$remaining = Config::getMaxDecompressedSize();
    }

    /**
     * Count decompressed octets against the limit.
     */
    private static function take(string $data): string
    {
        self::$remaining -= strlen($data);
        if (self::$remaining < 0) {
            throw new \RuntimeException(
                "Decompressed data exceeds the limit of " .
                    Config::getMaxDecompressedSize() .
                    " octets.",
            );
        }
        return $data;
    }

    private static function inflate(string $compressed, int $encoding): string
    {
        $context = \inflate_init($encoding);
        if ($context === false) {
            throw new \RuntimeException("Unable to initialize decompression.");
        }
        $data = "";
        $length = strlen($compressed);
        $offset = 0;
        do {
            $part = \inflate_add(
                $context,
                substr($compressed, $offset, self::CHUNK_SIZE),
                $offset + self::CHUNK_SIZE >= $length
                    ? ZLIB_FINISH
                    : ZLIB_SYNC_FLUSH,
            );
            if ($part === false) {
                throw new \RuntimeException("Decompression failed.");
            }
            $data .= self::take($part);
            $offset += self::CHUNK_SIZE;
        } while (
            $offset < $length &&
            \inflate_get_status($context) !== ZLIB_STREAM_END
        );
        if (\inflate_get_status($context) !== ZLIB_STREAM_END) {
            throw new \RuntimeException("Decompression failed.");
        }
        return $data;
    }

    private static function bunzip(string $compressed): string
    {
        $stream = \fopen("php://temp", "r+");
        \fwrite($stream, $compressed);
        \rewind($stream);
        $filter = \stream_filter_append(
            $stream,
            "bzip2.decompress",
            STREAM_FILTER_READ,
        );
        if ($filter === false) {
            \fclose($stream);
            throw new \RuntimeException("Unable to initialize decompression.");
        }
        $data = "";
        try {
            while (!\feof($stream)) {
                $part = \fread($stream, self::CHUNK_SIZE);
                if ($part === false) {
                    throw new \RuntimeException("Decompression failed.");
                }
                $data .= self::take($part);
            }
        } finally {
            \fclose($stream);
        }
        return $data;
    }
}
