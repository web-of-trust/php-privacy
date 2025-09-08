<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Signature;

use OpenPGP\Enum\{RevocationReasonTag, SignatureSubpacketType};
use OpenPGP\Packet\SignatureSubpacket;

/**
 * RevocationReason sub-packet class
 * Represents revocation reason OpenPGP signature sub packet.
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class RevocationReason extends SignatureSubpacket
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
            SignatureSubpacketType::RevocationReason->value,
            $data,
            $critical,
        );
    }

    /**
     * From revocation
     *
     * @param RevocationReasonTag $reason
     * @param string $description
     * @param bool $critical
     * @return self
     */
    public static function fromRevocation(
        RevocationReasonTag $reason,
        string $description,
        bool $critical = false,
    ): self {
        return new self(
            self::revocationToBytes($reason, $description),
            $critical,
        );
    }

    /**
     * Get reason
     *
     * @return RevocationReasonTag
     */
    public function getReason(): RevocationReasonTag
    {
        return RevocationReasonTag::from(ord($this->getData()[0]));
    }

    /**
     * Get description
     *
     * @return string
     */
    public function getDescription(): string
    {
        return substr($this->getData(), 1);
    }

    private static function revocationToBytes(
        RevocationReasonTag $reason,
        string $description,
    ): string {
        return implode([chr($reason->value), $description]);
    }
}
