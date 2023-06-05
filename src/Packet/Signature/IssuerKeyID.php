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

use phpseclib3\Common\Functions\Strings;
use OpenPGP\Enum\SignatureSubpacketType;
use OpenPGP\Packet\SignatureSubpacket;

/**
 * IssuerKeyID sub-packet class
 * Giving the issuer key ID.
 * 
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class IssuerKeyID extends SignatureSubpacket
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
            SignatureSubpacketType::IssuerKeyID->value,
            $data,
            $critical,
            $isLong
        );
    }

    /**
     * From key ID
     *
     * @param string $keyID
     * @param bool $critical
     * @return self
     */
    public static function fromKeyID(
        string $keyID, bool $critical = false
    ): self
    {
        return new self($keyID, $critical);
    }

    /**
     * From wildcard
     *
     * @param bool $critical
     * @return self
     */
    public static function wildcard(
        bool $critical = false
    ): self
    {
        return new self(str_repeat("\x00", 8), $critical);
    }

    /**
     * Get key ID
     * 
     * @param bool $toHex
     * @return string
     */
    public function getKeyID(bool $toHex = false): string
    {
        return $toHex ? Strings::bin2hex($this->getData()) : $this->getData();
    }
}
