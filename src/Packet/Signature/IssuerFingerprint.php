<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Signature;

use OpenPGP\Enum\SignatureSubpacketType;
use OpenPGP\Packet\SignatureSubpacket;
use OpenPGP\Type\KeyPacketInterface;
use phpseclib3\Common\Functions\Strings;

/**
 * IssuerFingerprint sub-packet class
 * Giving the issuer key fingerprint.
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class IssuerFingerprint extends SignatureSubpacket
{
    /**
     * Constructor
     *
     * @param string $data
     * @param bool $critical
     * @param bool $isLong
     * @return self
     */
    public function __construct(
        string $data,
        bool $critical = false,
        bool $isLong = false
    ) {
        parent::__construct(
            SignatureSubpacketType::IssuerFingerprint->value,
            $data,
            $critical,
            $isLong
        );
    }

    /**
     * From key package
     *
     * @param KeyPacketInterface $key
     * @param bool $critical
     * @return self
     */
    public static function fromKeyPacket(
        KeyPacketInterface $key,
        bool $critical = false
    ): self {
        return new self(
            chr($key->getVersion()) . $key->getFingerprint(),
            $critical
        );
    }

    /**
     * Create wildcard fingerprint sub-packet
     *
     * @param bool $isV6
     * @param bool $critical
     * @return self
     */
    public static function wildcard(
        bool $isV6 = true,
        bool $critical = false
    ): self {
        return new self(
            chr($isV6 ? 6 : 4) . str_repeat("\x00", $isV6 ? 32 : 20),
            $critical
        );
    }

    /**
     * Get key version
     *
     * @return int
     */
    public function getKeyVersion(): int
    {
        return ord($this->getData()[0]);
    }

    /**
     * Get key fingerprint
     *
     * @param bool $toHex
     * @return string
     */
    public function getKeyFingerprint(bool $toHex = false): string
    {
        return $toHex
            ? Strings::bin2hex(substr($this->getData(), 1))
            : substr($this->getData(), 1);
    }
}
