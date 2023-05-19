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
use OpenPGP\Enum\SignatureSubpacketType;
use OpenPGP\Packet\SignatureSubpacket;

/**
 * SignatureCreationTime sub-packet class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class SignatureCreationTime extends SignatureSubpacket
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
            SignatureSubpacketType::SignatureCreationTime->value,
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
     * Gets creation time
     * 
     * @return DateTime
     */
    public function getCreationTime(): DateTime
    {
        return (new DateTime())->setTimestamp(
            Helper::bytesToLong($this->getData())
        );
    }
}
