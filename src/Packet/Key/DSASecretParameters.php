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

use phpseclib3\Crypt\DSA\PrivateKey;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Math\BigInteger;

use OpenPGP\Enum\HashAlgorithm;

/**
 * DSA secret parameters class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class DSASecretParameters implements SignableParametersInterface
{
    use DSASigningTrait;

    /**
     * phpseclib3 DSA private key
     */
    private PrivateKey $privateKey;

    /**
     * Constructor
     *
     * @param BigInteger $exponent
     * @param DSAPublicParameters $publicParams
     * @return self
     */
    public function __construct(
        private BigInteger $exponent,
        DSAPublicParameters $publicParams
    )
    {
        $this->privateKey = PublicKeyLoader::loadPrivateKey([
            'p' => $publicParams->getPrime(),
            'q' => $publicParams->getOrder(),
            'g' => $publicParams->getGenerator(),
            'y' => $publicParams->getExponent(),
            'x' => $exponent,
        ]);
    }

    /**
     * Reads parameters from bytes
     *
     * @param string $bytes
     * @param DSAPublicParameters $publicParams
     * @return DSASecretParameters
     */
    public static function fromBytes(
        string $bytes, DSAPublicParameters $publicParams
    ): ElGamalSecretParameters
    {
        return DSASecretParameters(Helper::readMPI($bytes), $publicParams);
    }

    /**
     * Gets exponent x
     *
     * @return BigInteger
     */
    public function getExponent(): BigInteger
    {
        return $this->exponent;
    }

    /**
     * Gets private key
     *
     * @return PrivateKey
     */
    public function getPrivateKey(): PrivateKey
    {
        return $this->privateKey;
    }

    /**
     * {@inheritdoc}
     */
    public function encode(): string
    {
        return implode([
            pack('n', $this->exponent->getLength()),
            $this->exponent->toBytes(),
        ]);
    }
}
