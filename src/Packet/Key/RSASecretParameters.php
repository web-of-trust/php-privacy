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

use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\PrivateKey;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Math\BigInteger;

use OpenPGP\Common\Helper;
use OpenPGP\Enum\{HashAlgorithm, RSAKeySize};

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
    private readonly PrivateKey $privateKey;

    /**
     * Constructor
     *
     * @param BigInteger $exponent
     * @param BigInteger $primeP
     * @param BigInteger $primeQ
     * @param BigInteger $coefficients
     * @param RSAPublicParameters $publicParams
     * @param PrivateKey $privateKey
     * @return self
     */
    public function __construct(
        private readonly BigInteger $exponent,
        private readonly BigInteger $primeP,
        private readonly BigInteger $primeQ,
        private readonly BigInteger $coefficients,
        private readonly RSAPublicParameters $publicParams,
        ?PrivateKey $privateKey = null
    )
    {
        $this->privateKey = $privateKey ?? PublicKeyLoader::loadPrivateKey([
            'e' => $publicParams->getExponent(),
            'n' => $publicParams->getModulus(),
            'd' => $exponent,
            'p' => $primeP,
            'q' => $primeQ,
        ]);
    }

    /**
     * Reads parameters from bytes
     *
     * @param string $bytes
     * @param RSAPublicParameters $publicParams
     * @return RSASecretParameters
     */
    public static function fromBytes(
        string $bytes, RSAPublicParameters $publicParams
    ): RSASecretParameters
    {
        $exponent = Helper::readMPI($bytes);

        $offset = $exponent->getLengthInBytes() + 2;
        $primeP = Helper::readMPI(substr($bytes, $offset));

        $offset += $primeP->getLengthInBytes() + 2;
        $primeQ = Helper::readMPI(substr($bytes, $offset));

        $offset += $primeQ->getLengthInBytes() + 2;
        $coefficients = Helper::readMPI(substr($bytes, $offset));

        return new RSASecretParameters(
            $exponent, $primeP, $primeQ, $coefficients, $publicParams
        );
    }

    /**
     * Generates parameters by using RSA create key
     *
     * @param RSAKeySize $keySize
     * @return RSASecretParameters
     */
    public static function generate(RSAKeySize $keySize): RSASecretParameters
    {
        $privateKey = RSA::createKey($keySize->value);
        $rawKey = RSA::createKey($keySize->value)->toString('Raw');
        return new RSASecretParameters(
            $rawKey['d'],
            $rawKey['primes'][1],
            $rawKey['primes'][2],
            $rawKey['coefficients'],
            new RSAPublicParameters(
                $rawKey['n'],
                $rawKey['e'],
                $privateKey->getPublicKey()
            ),
            $privateKey
        );
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
    public function getPublicParams(): KeyParametersInterface
    {
        return $this->publicParams;
    }

    /**
     * {@inheritdoc}
     */
    public function isValid(): bool
    {
        $one = new BigInteger(1);
        $two = new BigInteger(2);

        // expect pq = n
        if (!$this->primeP->multiply($this->primeQ)->equals($this->publicParams->getModulus())) {
            return false;
        }

        // expect p*u = 1 mod q
        list(, $c) = $this->primeP->multiply($this->coefficients)->divide($this->primeQ);
        if (!$c->equals($one)) {
            return false;
        }

        $nSizeOver3 = floor($this->publicParams->getModulus()->getLength() / 3);
        $r = BigInteger::randomRange($one, $two->bitwise_leftShift($nSizeOver3));
        $rde = $r->multiply($this->exponent)->multiply($this->publicParams->getExponent());

        list(, $p) = $rde->divide($this->primeP->subtract($one));
        list(, $q) = $rde->divide($this->primeQ->subtract($one));
        return $p->equals($r) && $q->equals($r);
    }

    /**
     * {@inheritdoc}
     */
    public function encode(): string
    {
        return implode([
            pack('n', $this->exponent->getLength()),
            $this->exponent->toBytes(),
            pack('n', $this->primeP->getLength()),
            $this->primeP->toBytes(),
            pack('n', $this->primeQ->getLength()),
            $this->primeQ->toBytes(),
            pack('n', $this->coefficients->getLength()),
            $this->coefficients->toBytes(),
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
