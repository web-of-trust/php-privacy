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
use phpseclib3\Crypt\RSA\PublicKey;
use phpseclib3\Math\BigInteger;

use OpenPGP\Helper;

/**
 * RSA public parameters class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class RSAPublicParameters implements VerifiableParametersInterface
{
    /**
     * phpseclib3 RSA public key
     */
    private PublicKey $publicKey;

    /**
     * Constructor
     *
     * @param BigInteger $modulus
     * @param BigInteger $publicExponent
     * @return self
     */
    public function __construct(
        private BigInteger $modulus,
        private BigInteger $exponent
    )
    {
        $this->publicKey = PublicKeyLoader::loadPublicKey([
            'e' => $exponent,
            'n' => $modulus,
        ]);
    }

    /**
     * Reads parameters from bytes
     *
     * @param string $bytes
     * @return RSAPublicParameters
     */
    public static function fromBytes(string $bytes): RSAPublicParameters
    {
        $modulus = Helper::readMPI($bytes);
        $exponent = Helper::readMPI(substr($bytes, $modulus->getLengthInBytes() + 2));
        return RSAPublicParameters($modulus, $exponent);
    }

    /**
     * Gets public key
     *
     * @return PublicKey
     */
    public function getPublicKey(): PublicKey
    {
        return $this->publicKey;
    }

    /**
     * Gets modulus n
     *
     * @return BigInteger
     */
    public function getModulus(): BigInteger
    {
        return $this->modulus;
    }

    /**
     * Gets exponent e
     *
     * @return BigInteger
     */
    public function getExponent(): BigInteger
    {
        return $this->exponent;
    }

    /**
     * {@inheritdoc}
     */
    public function encode(): string
    {
        return implode([
            pack('n', $this->modulus->getLength()),
            $this->modulus->toBytes(true),
            pack('n', $this->exponent->getLength()),
            $this->exponent->toBytes(true),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function verify(
        string $message,
        HashAlgorithm $hash,
        string $signature
    ): bool
    {
        return $this->publicKey->withHash($hash->name)->verify(
            $message, Helper::readMPI($signature).toBytes(true)
        );
    }
}
