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
        $bodyBytes = $this->toBytes();
        $bodyLen = strlen($bodyBytes);
        $data = [];

        $hdr = 0x80 | 0x40 | $this->tag->value;
        if ($bodyLen < 192) {
            $data = [chr($hdr), chr($bodyLen)];
        }
        elseif ($bodyLen <= 8383) {
            $data = [
              chr($hdr),
              chr(((($bodyLen - 192) >> 8) & 0xff) + 192),
              chr($bodyLen - 192),
            ];
        }
        else {
            $data = [chr($hdr), "\xff", pack('N', $bodyLen)];
        }
        $data[] = $bodyBytes;

        return implode($data);
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
