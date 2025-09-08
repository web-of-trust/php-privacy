<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Signature;

use DateTimeInterface;
use OpenPGP\Common\Helper;
use OpenPGP\Enum\SignatureSubpacketType;
use OpenPGP\Packet\SignatureSubpacket;

/**
 * SignatureExpirationTime sub-packet class
 * Giving signature expiration time.
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class SignatureExpirationTime extends SignatureSubpacket
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
            SignatureSubpacketType::SignatureExpirationTime->value,
            $data,
            $critical,
        );
    }

    /**
     * From time
     *
     * @param DateTimeInterface $time
     * @param bool $critical
     * @return self
     */
    public static function fromTime(
        DateTimeInterface $time,
        bool $critical = false,
    ): self {
        return new self(pack("N", $time->getTimestamp()), $critical);
    }

    /**
     * Get expiration time
     *
     * @return DateTimeInterface
     */
    public function getExpirationTime(): DateTimeInterface
    {
        return new \DateTime()->setTimestamp(
            Helper::bytesToLong($this->getData()),
        );
    }
}
