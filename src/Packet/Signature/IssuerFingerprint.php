<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Signature;

use OpenPGP\Enum\SignatureSubpacketType;
use OpenPGP\Packet\{KeyPacketInterface, SignatureSubpacket};

/**
 * IssuerFingerprint sub-packet class
 * Giving the issuer key fingerprint.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
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
    )
    {
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
     * @return IssuerFingerprint
     */
    public static function fromKeyPacket(
        KeyPacketInterface $key, bool $critical = false
    ): IssuerFingerprint
    {
        return IssuerFingerprint($key->getVersion(), $key->getFingerprint(), $critical);
    }

    /**
     * Gets key version
     * 
     * @return int
     */
    public function getKeyVersion(): int
    {
        return ord($this->data[0]);
    }

    /**
     * Gets fingerprint
     * 
     * @return string
     */
    public function getKeyFingerprint(): string
    {
        return substr($this->data, 1);
    }
}
