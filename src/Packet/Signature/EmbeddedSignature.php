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
use OpenPGP\Packet\Signature;
use OpenPGP\Packet\SignatureSubpacket;

/**
 * EmbeddedSignature sub-packet class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class EmbeddedSignature extends SignatureSubpacket
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
            SignatureSubpacketType::EmbeddedSignature->value,
            $data,
            $critical,
            $isLong
        );
    }

    /**
     * Embed signature package
     *
     * @param Signature $signature
     * @return EmbeddedSignature
     */
    public static function fromSignature(Signature $signature): EmbeddedSignature
    {
        return EmbeddedSignature($signature->toBytes());
    }
}
