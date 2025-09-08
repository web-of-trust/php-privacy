<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Common\Helper;
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
    const int PARTIAL_MIN_SIZE = 512;
    const int PARTIAL_MAX_SIZE = 1024;

    /**
     * Constructor
     *
     * @param PacketTag $tag
     * @return self
     */
    protected function __construct(private readonly PacketTag $tag) {}

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
        return match ($this->tag) {
            PacketTag::AeadEncryptedData,
            PacketTag::CompressedData,
            PacketTag::LiteralData,
            PacketTag::SymEncryptedData,
            PacketTag::SymEncryptedIntegrityProtectedData
                => $this->partialEncode(),
            default => $this->simpleEncode(),
        };
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
     * Get encode tag byte
     *
     * @return string
     */
    protected function getTagByte(): string
    {
        return chr(0xc0 | $this->tag->value);
    }

    /**
     * Encode package to the openpgp body specifier
     *
     * @return string
     */
    private function simpleEncode(): string
    {
        $bytes = $this->toBytes();
        return implode([
            $this->getTagByte(),
            Helper::simpleLength(strlen($bytes)),
            $bytes,
        ]);
    }

    /**
     * Encode package to the openpgp partial body specifier
     *
     * @return string
     */
    private function partialEncode(): string
    {
        $data = $this->toBytes();
        $dataLen = strlen($data);
        $partialData = [];

        while ($dataLen >= self::PARTIAL_MIN_SIZE) {
            $maxSize = min(self::PARTIAL_MAX_SIZE, $dataLen);
            $powerOf2 = min((log($maxSize) / M_LN2) | 0, 30);
            $chunkSize = 1 << $powerOf2;

            $partialData[] = implode([
                chr(224 + $powerOf2),
                Strings::shift($data, $chunkSize),
            ]);
            $dataLen = strlen($data);
        }
        $partialData[] = implode([Helper::simpleLength($dataLen), $data]);

        return implode([$this->getTagByte(), ...$partialData]);
    }
}
