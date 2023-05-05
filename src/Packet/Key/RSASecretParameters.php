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

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA\PrivateKey;
use phpseclib3\Math\BigInteger;

use OpenPGP\Enum\HashAlgorithm;

/**
 * RSA secret parameters class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class RSASecretParameters implements SignableParametersInterface
{
    /**
     * phpseclib3 RSA private key
     */
    private PrivateKey $privateKey;

    /**
     * Constructor
     *
     * @param BigInteger $exponent
     * @param BigInteger $primeP
     * @param BigInteger $primeQ
     * @param BigInteger $coefficients
     * @param RSAPublicParameters $publicParams
     * @return self
     */
    public function __construct(
        private BigInteger $exponent,
        private BigInteger $primeP,
        private BigInteger $primeQ,
        private BigInteger $coefficients,
        RSAPublicParameters $publicParams
    )
    {
        $this->privateKey = PublicKeyLoader::loadPrivateKey([
            'e' => $publicParams->getExponent(),
            'n' => $publicParams->getModulus(),
            'd' => $exponent,
            'p' => $primeP,
            'q' => $primeQ,
        ]);
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
     * Gets exponent d
     *
     * @return BigInteger
     */
    public function getExponent(): BigInteger
    {
        return $this->exponent;
    }

    /**
     * Gets prime value p
     *
     * @return BigInteger
     */
    public function getPrimeP(): BigInteger
    {
        return $this->primeP;
    }

    /**
     * Gets prime value q (p < q)
     *
     * @return BigInteger
     */
    public function getPrimeQ(): BigInteger
    {
        return $this->primeQ;
    }

    /**
     * Gets coefficients
     *
     * @return BigInteger
     */
    public function getCoefficients(): BigInteger
    {
        return $this->coefficients;
    }

    /**
     * {@inheritdoc}
     */
    public function encode(): string
    {
        return implode([
            pack('n', $this->exponent->getLength()),
            $this->exponent->toBytes(true),
            pack('n', $this->primeP->getLength()),
            $this->primeP->toBytes(true),
            pack('n', $this->primeQ->getLength()),
            $this->primeQ->toBytes(true),
            pack('n', $this->coefficients->getLength()),
            $this->coefficients->toBytes(true),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function sign(string $message, HashAlgorithm $hash): string
    {
        $signature = $this->privateKey->withHash($hash->name)->sign($message);
        return implode([
            pack('n', strlen($signature) * 8),
            $signature,
        ]);
    }
}
