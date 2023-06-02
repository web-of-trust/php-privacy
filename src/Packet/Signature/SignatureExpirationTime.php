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

use DateTime;
use OpenPGP\Common\Helper;
use OpenPGP\Enum\SignatureSubpacketType;
use OpenPGP\Packet\SignatureSubpacket;

/**
 * SignatureExpirationTime sub-packet class
 * Giving giving signature expiration time.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class SignatureExpirationTime extends SignatureSubpacket
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
            SignatureSubpacketType::SignatureExpirationTime->value,
            $data,
            $critical,
            $isLong
        );
    }

    /**
     * From time
     *
     * @param DateTime $time
     * @param bool $critical
     * @return self
     */
    public static function fromTime(
        DateTime $time, bool $critical = false
    ): self
    {
        return new self(pack('N', $time->getTimestamp()), $critical);
    }

    /**
     * Get expiration time
     * 
     * @return DateTime
     */
    public function getExpirationTime(): DateTime
    {
        return (new DateTime())->setTimestamp(
            Helper::bytesToLong($this->getData())
        );
    }
}
