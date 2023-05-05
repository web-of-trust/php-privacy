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
use phpseclib3\Math\BigInteger;

/**
 * RSASessionKeyCryptor class.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class RSASessionKeyCryptor implements SessionKeyCryptorInterface
{
    /**
     * Constructor
     *
     * @param RSAPublicParameters $keyParams
     * @param BigInteger $encrypted
     * @return self
     */
    public function __construct(
        private RSAPublicParameters $keyParams,
        private BigInteger $encrypted
    )
    {
        $this->keyParams->getPublicKey()->withPadding(RSA::ENCRYPTION_PKCS1);
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(SessionKey $sessionKey): SessionKeyCryptorInterface
    {
        $publicKey = $this->keyParams->getPublicKey()->withPadding(RSA::ENCRYPTION_PKCS1);
        $encrypted = $publicKey->encrypt(implode([
            $sessionKey->encode(),
            $sessionKey->computeChecksum(),
        ]));
        return new RSASessionKeyCryptor($this->keyParams, Helper::bin2BigInt($encrypted));
    }

    /**
     * Decrypts session key
     * 
     * @param RSASecretParameters $keyParams
     * @return SessionKey
     */
    public function decrypt(RSASecretParameters $keyParams): SessionKey
    {
        $privateKey = $keyParams->getPrivateKey()->withPadding(RSA::ENCRYPTION_PKCS1);
        $decrypted = $privateKey->decrypt(
            $this->encrypted->toBytes(true)
        );
        return SessionKey::fromBytes($decrypted);
    }

    /**
     * {@inheritdoc}
     */
    public function encode(): string
    {
        return implode([
            pack('n', $this->encrypted->getLength()),
            $this->encrypted->toBytes(true),
        ]);
    }
}
