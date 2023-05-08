<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use phpseclib3\Math\BigInteger;

/**
 * ECDH secret parameters class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class ECDHSecretParameters extends ECSecretParameters
{
    /**
     * Constructor
     *
     * @param BigInteger $d
     * @param ECDHPublicParameters $publicParams
     * @return self
     */
    public function __construct(
        BigInteger $d,
        ECDHPublicParameters $publicParams
    )
    {
        parent::__construct($d, $publicParams);
    }

    /**
     * Reads parameters from bytes
     *
     * @param string $bytes
     * @param ECDHPublicParameters $publicParams
     * @return ECDHSecretParameters
     */
    public static function fromBytes(
        string $bytes, ECDHPublicParameters $publicParams
    ): ElGamalSecretParameters
    {
        return ECDHSecretParameters(Helper::readMPI($bytes), $publicParams);
    }
}
