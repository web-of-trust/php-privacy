<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Enum\PacketTag;
use OpenPGP\Common\Config;
use OpenPGP\Type\PacketInterface;
use Psr\Log\{LoggerAwareInterface, LoggerAwareTrait, LoggerInterface};

/**
 * Abstract packet class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
abstract class AbstractPacket implements
    LoggerAwareInterface,
    PacketInterface,
    \Stringable
{
    use LoggerAwareTrait;

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
        $this->setLogger(Config::getLogger());
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
    public function getLogger(): LoggerInterface
    {
        return $this->logger ?? Config::getLogger();
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
     * Encode package to the openpgp body specifier
     *
     * @return string
     */
    private function simpleEncode(): string
    {
        $bytes = $this->toBytes();
        return implode([
            chr(0xc0 | $this->tag->value),
            self::bodyLength(strlen($bytes)),
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
        $offset = 0;
        $partialData = [];

        while ($dataLen - $offset >= self::PARTIAL_MIN_SIZE) {
            $maxSize = min(self::PARTIAL_MAX_SIZE, $dataLen - $offset);
            $powerOf2 = min((int) floor(log($maxSize) / M_LN2), 30);
            $chunkSize = 1 << $powerOf2;
            $partialData[] = implode([
                chr(224 + $powerOf2),
                substr($data, $offset, $chunkSize),
            ]);
            $offset += $chunkSize;
        }
        $rest = substr($data, $offset);
        $partialData[] = implode([self::bodyLength(strlen($rest)), $rest]);

        return implode([chr(0xc0 | $this->tag->value), ...$partialData]);
    }

    /**
     * Encode a given integer of length to the openpgp body length specifier
     *
     * @param int $length
     * @return string
     */
    private static function bodyLength(int $length): string
    {
        if ($length < 192) {
            return chr($length);
        } elseif ($length > 191 && $length < 8384) {
            return implode([
                chr((($length - 192 >> 8) & 0xff) + 192),
                chr(($length - 192) & 0xff),
            ]);
        } else {
            return implode(["\xff", pack("N", $length)]);
        }
    }
}
