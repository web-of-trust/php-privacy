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

/**
 * TrustSignature sub-packet class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class TrustSignature extends SignatureSubpacket
{
    /**
     * Constructor
     *
     * @param string $data
     * @param bool $critical
     * @return self
     */
    public function __construct(string $data, bool $critical = false)
    {
        parent::__construct(
            SignatureSubpacketType::TrustSignature->value,
            $data,
            $critical,
        );
    }

    /**
     * Get trust level
     *
     * @return int
     */
    public function getTrustLevel(): int
    {
        return ord($this->getData()[0]);
    }

    /**
     * Get trust amount
     *
     * @return int
     */
    public function getTrustAmount(): int
    {
        return ord($this->getData()[1]);
    }
}
