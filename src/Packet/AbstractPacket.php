<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Common\{Config, Helper};
use OpenPGP\Enum\PacketTag;
use OpenPGP\Type\PacketInterface;
use phpseclib3\Common\Functions\Strings;

/**
 * Abstract packet class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
abstract class AbstractPacket implements PacketInterface
{
    /**
     * Packet tag support partial body length
     */
    const PARTIAL_SUPPORTING = [
        PacketTag::AeadEncryptedData,
        PacketTag::CompressedData,
        PacketTag::LiteralData,
        PacketTag::SymmetricallyEncryptedData,
        PacketTag::SymmetricallyEncryptedIntegrityProtectedData,
    ];

    const PARTIAL_MIN_SIZE = 512;
    const PARTIAL_MAX_SIZE = 1024;

    /**
     * Constructor
     *
     * @param PacketTag $tag
     * @return self
     */
    protected function __construct(private readonly PacketTag $tag)
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getTag(): PacketTag
    {
        return $this->tag;
    }

    /**
     * {@inheritdoc}
     */
    public function encode(): string
    {
        if (in_array($this->tag, self::PARTIAL_SUPPORTING, true)) {
            return $this->partialEncode();
        } else {
            $bytes = $this->toBytes();
            return implode([
                chr(0xc0 | $this->tag->value),
                Helper::simpleLength(strlen($bytes)),
                $bytes,
            ]);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function __toString(): string
    {
        return $this->encode();
    }

    /**
     * {@inheritdoc}
     */
    abstract public function toBytes(): string;

    /**
     * Encode package to the openpgp partial body specifier
     *
     * @return string
     */
    private function partialEncode(): string
    {
        $data = $this->toBytes();
        $partialData = [];

        while (strlen($data) >= self::PARTIAL_MIN_SIZE) {
            $maxSize = strlen(substr($data, 0, self::PARTIAL_MAX_SIZE));
            $powerOf2 = min((log($maxSize) / M_LN2) | 0, 30);
            $chunkSize = 1 << $powerOf2;

            $partialData[] = implode([
                chr(224 + $powerOf2),
                Strings::shift($data, $chunkSize),
            ]);
        }
        $partialData[] = implode([Helper::simpleLength(strlen($data)), $data]);

        return implode([chr(0xc0 | $this->tag->value), ...$partialData]);
    }
}
