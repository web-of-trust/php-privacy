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
use OpenPGP\Cryptor\Asymmetric\{ElGamalPrivateKey, ElGamalPublicKey};

/**
 * ElGamalSessionKeyParameters class.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class ElGamalSessionKeyParameters implements SessionKeyParametersInterface
{
    /**
     * Constructor
     *
     * @param BigInteger $gamma MPI of Elgamal (Diffie-Hellman) value g**k mod p.
     * @param BigInteger $phi MPI of Elgamal (Diffie-Hellman) value m * y**k mod p.
     * @return self
     */
    public function __construct(
        private readonly BigInteger $gamma,
        private readonly BigInteger $phi
    )
    {
    }

    /**
     * Reads encrypted session key parameters from bytes
     *
     * @param string $bytes
     * @return ElGamalSessionKeyParameters
     */
    public static function fromBytes(string $bytes): ElGamalSessionKeyParameters
    {
        $gamma = Helper::readMPI($bytes);
        $phi = Helper::readMPI(substr($bytes, $gamma->getLengthInBytes() + 2));
        return new ElGamalSessionKeyParameters($gamma, $phi);
    }

    /**
     * Produces parameters by encrypting session key
     *
     * @param SessionKey $sessionKey
     * @param ElGamalPublicKey $publicKey
     * @return ElGamalSessionKeyParameters
     */
    public static function produceParameters(
        SessionKey $sessionKey, ElGamalPublicKey $publicKey
    ): ElGamalSessionKeyParameters
    {
        $encrypted = $publicKey->encrypt(implode([
            $sessionKey->encode(),
            $sessionKey->computeChecksum(),
        ]));
        $size = ($publicKey->getBitSize() + 7) >> 3;
        return new ElGamalSessionKeyParameters(
            Helper::bin2BigInt(substr($encrypted, 0, $size)),
            Helper::bin2BigInt(substr($encrypted, $size, $size))
        );
    }

    /**
     * {@inheritdoc}
     */
    public function encode(): string
    {
        return implode([
            pack('n', $this->gamma->getLength()),
            $this->gamma->toBytes(),
            pack('n', $this->phi->getLength()),
            $this->phi->toBytes(),
        ]);
    }

    /**
     * Gets gamma
     *
     * @return BigInteger
     */
    public function getGamma(): BigInteger
    {
        return $this->gamma;
    }

    /**
     * Gets phi
     *
     * @return BigInteger
     */
    public function getPhi(): BigInteger
    {
        return $this->phi;
    }

    /**
     * Decrypts session key by using private key
     *
     * @param ElGamalPrivateKey $privateKey
     * @return SessionKey
     */
    public function decrypt(ElGamalPrivateKey $privateKey): SessionKey
    {
        return SessionKey::fromBytes(self::pkcs1Decode(
            $privateKey->decrypt(implode([
                $this->gamma->toBytes(),
                $this->phi->toBytes(),
            ]))
        ));
    }

    /**
     * Remove pkcs1 padding from a message
     * 
     * @return string
     */
    private static function pkcs1Decode(string $message)
    {
        $offset = 2;
        $separatorNotFound = 1;
        for ($j = $offset; $j < strlen($message); $j++) {
            $separatorNotFound &= (ord($message[$j]) != 0) ? 1 : 0;
            $offset += $separatorNotFound;
        }
        return substr($message, $offset + 1);
    }
}
