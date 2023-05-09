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
use OpenPGP\Common\Helper;

/**
 * ECDSA secret parameters class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class ECDSASecretParameters extends ECSecretParameters implements SignableParametersInterface
{
    use DSASigningTrait;

    /**
     * Constructor
     *
     * @param BigInteger $d
     * @param ECDSAPublicParameters $publicParams
     * @return self
     */
    public function __construct(
        BigInteger $d,
        ECDSAPublicParameters $publicParams
    )
    {
        parent::__construct($d, $publicParams);
    }

    /**
     * Reads parameters from bytes
     *
     * @param string $bytes
     * @param ECDSAPublicParameters $publicParams
     * @return ECDSASecretParameters
     */
    public static function fromBytes(
        string $bytes, ECDSAPublicParameters $publicParams
    ): ECDSASecretParameters
    {
        return new ECDSASecretParameters(Helper::readMPI($bytes), $publicParams);
    }
}
