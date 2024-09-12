<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Enum\{
    HashAlgorithm,
    PacketTag,
    SymmetricAlgorithm,
};
use OpenPGP\Common\Config;
use OpenPGP\Type\PacketInterface;
use Psr\Log\{
    LoggerAwareInterface,
    LoggerAwareTrait,
    LoggerInterface,
};

/**
 * Abstract packet class
 * 
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
abstract class AbstractPacket implements LoggerAwareInterface, PacketInterface, \Stringable
{
    use LoggerAwareTrait;

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
        $bytes = $this->toBytes();
        return implode([
            chr(0xc0 | $this->tag->value),
            self::simpleLength(strlen($bytes)),
            $bytes,
        ]);
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
     * Encode a given integer of length to the openpgp length specifier to a string
     *
     * @param int $length
     * @return string
     */
    public static function simpleLength(int $length): string
    {
        if ($length < 192) {
            return chr($length);
        }
        elseif ($length > 191 && $length < 8384) {
            return implode([
              chr(((($length - 192) >> 8) & 0xff) + 192),
              chr(($length - 192) & 0xff),
            ]);
        }
        else {
            return implode(["\xff", pack('N', $length)]);
        }
    }

    protected static function validateHash(HashAlgorithm $hash): void
    {
        switch ($hash) {
            case HashAlgorithm::Unknown:
            case HashAlgorithm::Md5:
            case HashAlgorithm::Sha1:
            case HashAlgorithm::Ripemd160:
                throw new \UnexpectedValueException(
                    "Hash {$hash->name} is unsupported.",
                );
                break;
        }
    }

    protected static function validateSymmetric(SymmetricAlgorithm $Symmetric): void
    {
        switch ($symmetric) {
            case SymmetricAlgorithm::Plaintext:
            case SymmetricAlgorithm::Idea:
            case SymmetricAlgorithm::TripleDes:
            case SymmetricAlgorithm::Cast5:
                throw new \UnexpectedValueException(
                    "Symmetric {$symmetric->name} is unsupported.",
                );
                break;
        }
    }
}
