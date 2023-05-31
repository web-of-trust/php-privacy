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

use phpseclib3\Crypt\Common\AsymmetricKey;
use phpseclib3\Crypt\Random;
use phpseclib3\Math\BigInteger;
use OpenPGP\Common\Helper;
use OpenPGP\Cryptor\Asymmetric\ElGamal\{
    PrivateKey,
    PublicKey,
};
use OpenPGP\Type\SessionKeyInterface;

/**
 * ElGamal session key cryptor class.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class ElGamalSessionKeyCryptor extends SessionKeyCryptor
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
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        $gamma = Helper::readMPI($bytes);
        $phi = Helper::readMPI(
            substr($bytes, $gamma->getLengthInBytes() + 2)
        );
        return new self($gamma, $phi);
    }

    /**
     * Produces cryptor by encrypting session key
     *
     * @param SessionKeyInterface $sessionKey
     * @param AsymmetricKey $publicKey
     * @return self
     */
    public static function encryptSessionKey(
        SessionKeyInterface $sessionKey, AsymmetricKey $publicKey
    ): self
    {
        if ($publicKey instanceof PublicKey) {
            $size = ($publicKey->getBitSize() + 7) >> 3;
            $padded = self::pkcs1Encode(implode([
                $sessionKey->toBytes(),
                $sessionKey->computeChecksum(),
            ]), $size);
            $encrypted = $publicKey->encrypt($padded);
            return new self(
                Helper::bin2BigInt(substr($encrypted, 0, $size)),
                Helper::bin2BigInt(substr($encrypted, $size, $size))
            );
        }
        else {
            throw new \InvalidArgumentException(
                'Public key is not instance of ElGamal key'
            );
        }
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
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
     * {@inheritdoc}
     */
    protected function decrypt(AsymmetricKey $privateKey): string
    {
        if ($privateKey instanceof PrivateKey) {
            return self::pkcs1Decode(
                $privateKey->decrypt(implode([
                    $this->gamma->toBytes(),
                    $this->phi->toBytes(),
                ]))
            );
        }
        else {
            throw new \InvalidArgumentException(
                'Private key is not instance of ElGamal key'
            );
        }
    }

    /**
     * Create a EME-PKCS1-v1_5 padded message
     * 
     * @return string
     */
    private static function pkcs1Encode(string $message, int $keyLength): string
    {
        $mLength = strlen($message);

        // length checking
        if ($mLength > $keyLength - 11) {
            throw new \UnexpectedValueException('Message too long');
        }
        $ps = self::pkcs1Padding($keyLength - $mLength - 3);
        $encoded = str_repeat("\x00", $keyLength);
        $encoded[1] = "\x02";
        $encoded = substr_replace($encoded, $ps, 2, strlen($ps));
        $encoded = substr_replace(
            $encoded, $message, $keyLength - $mLength, strlen($message)
        );
        return $encoded;
    }

    /**
     * Decode a EME-PKCS1-v1_5 padded message
     * 
     * @return string
     */
    private static function pkcs1Decode(string $message): string
    {
        $offset = 2;
        $separatorNotFound = 1;
        for ($j = $offset; $j < strlen($message); $j++) {
            $separatorNotFound &= (ord($message[$j]) != 0) ? 1 : 0;
            $offset += $separatorNotFound;
        }
        return substr($message, $offset + 1);
    }

    private static function pkcs1Padding(int $length): string
    {
        $result = str_repeat("\x00", $length);
        $count = 0;
        while ($count < $length) {
            $bytes = Random::string($length - $count);
            $strlen = strlen($bytes);
            for ($i = 0; $i < $strlen; $i++) {
                if (ord($bytes[$i]) != 0) {
                    $result[$count++] = $bytes[$i];
                }
            }
        };
        return $result;
    }
}
