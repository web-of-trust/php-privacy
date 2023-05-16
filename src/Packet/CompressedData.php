<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Enum\CompressionAlgorithm as Algorithm;
use OpenPGP\Enum\PacketTag;

/**
 * Implementation of the Compressed Data Packet (Tag 8)
 * 
 * The Compressed Data packet contains compressed data.
 * Typically, this packet is found as the contents of an encrypted packet,
 * or following a Signature or One-Pass Signature packet, and contains a literal data packet.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class CompressedData extends AbstractPacket
{
    /**
     * Default zip/zlib compression level, between 1 and 9
     */
    const DEFLATE_LEVEL = 6;

    /**
     * Constructor
     *
     * @param string $compressed
     * @param PacketList $packets
     * @param Algorithm $algorithm
     * @return self
     */
    public function __construct(
        private readonly string $compressed,
        private readonly PacketList $packets,
        private readonly Algorithm $algorithm = Algorithm::Uncompressed
    )
    {
        parent::__construct(PacketTag::CompressedData);
    }

    /**
     * Reads compressed data packet from byte string
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        $algorithm = Algorithm::from(ord($bytes[0]));
        $compressed = substr($bytes, 1);
        return new self(
            $compressed,
            self::decompress($compressed, $algorithm),
            $algorithm
        );
    }

    /**
     * Build compressed data packet from packet list
     *
     * @param PacketList $function
     * @param Algorithm $algorithm
     * @return self
     */
    public static function fromPacketList(
        PacketList $packets,
        Algorithm $algorithm = Algorithm::Uncompressed
    ): self
    {
        return new self(
            self::compress($packets, $algorithm),
            $packets,
            $algorithm
        );
    }

    /**
     * Gets compressed data
     *
     * @return string
     */
    public function getCompressed(): string
    {
        return $this->compressed;
    }

    /**
     * Gets decompressed packets contained within.
     *
     * @return PacketList
     */
    public function getPackets(): PacketList
    {
        return $this->packets;
    }

    /**
     * Gets compression algorithm
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
        return implode([
            chr($this->algorithm->value),
            $this->compressed,
        ]);
    }

    private static function compress(
        PacketList $packets, Algorithm $algorithm
    ): string
    {
        return match($algorithm) {
            Algorithm::Uncompressed => $packets->encode(),
            Algorithm::Zip => \gzdeflate($packets->encode(), self::DEFLATE_LEVEL),
            Algorithm::Zlib => \gzcompress($packets->encode(), self::DEFLATE_LEVEL),
            Algorithm::BZip2 => \bzcompress($packets->encode()),
        };
    }

    private static function decompress(
        string $compressed, Algorithm $algorithm
    ): PacketList
    {
        return match($algorithm) {
            Algorithm::Uncompressed => PacketList::decode($compressed),
            Algorithm::Zip => PacketList::decode(\gzinflate($compressed)),
            Algorithm::Zlib => PacketList::decode(\gzuncompress($compressed)),
            Algorithm::BZip2 => PacketList::decode(\bzdecompress($compressed)),
        };
    }
}
