<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Common\Helper;
use OpenPGP\Type\SessionKeyInterface;
use phpseclib3\Crypt\Common\AsymmetricKey;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\{
    PrivateKey,
    PublicKey,
};
use phpseclib3\Math\BigInteger;

/**
 * RSA session key cryptor class.
 * 
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class RSASessionKeyCryptor extends SessionKeyCryptor
{
    /**
     * Constructor
     *
     * @param BigInteger $encrypted
     * @return self
     */
    public function __construct(
        private readonly BigInteger $encrypted
    )
    {
    }

    /**
     * Read encrypted session key from byte string
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(
        string $bytes
    ): self
    {
        return new self(Helper::readMPI($bytes));
    }

    /**
     * Produce cryptor by encrypting session key
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
            $publicKey = $publicKey->withPadding(RSA::ENCRYPTION_PKCS1);
            return new self(
                Helper::bin2BigInt($publicKey->encrypt(implode([
                    $sessionKey->toBytes(),
                    $sessionKey->computeChecksum(),
                ])))
            );
        }
        else {
            throw new \InvalidArgumentException(
                'Public key is not instance of RSA key.'
            );
        }
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            pack('n', $this->encrypted->getLength()),
            $this->encrypted->toBytes(),
        ]);
    }

    /**
     * Get encrypted session key
     *
     * @return BigInteger
     */
    public function getEncrypted(): BigInteger
    {
        return $this->encrypted;
    }

    /**
     * {@inheritdoc}
     */
    protected function decrypt(AsymmetricKey $privateKey): string
    {
        if ($privateKey instanceof PrivateKey) {
            $privateKey = $privateKey->withPadding(RSA::ENCRYPTION_PKCS1);
            return $privateKey->decrypt(
                $this->encrypted->toBytes()
            );
        }
        else {
            throw new \InvalidArgumentException(
                'Private key is not instance of RSA key.'
            );
        }
    }
}
