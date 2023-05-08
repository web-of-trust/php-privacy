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
 * ElGamalSessionKeyCryptor class.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class ElGamalSessionKeyCryptor implements SessionKeyCryptorInterface
{
    /**
     * Constructor
     *
     * @param ElGamalPublicParameters $keyParams
     * @param BigInteger $gamma
     * @param BigInteger $phi
     * @return self
     */
    public function __construct(
        private ElGamalPublicParameters $keyParams,
        private BigInteger $gamma,
        private BigInteger $phi
    )
    {
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(SessionKey $sessionKey): SessionKeyCryptorInterface
    {
        $publicKey = $this->keyParams->getPublicKey();
        $encrypted = $publicKey->encrypt(implode([
            $sessionKey->encode(),
            $sessionKey->computeChecksum(),
        ]));
        $size = ($publicKey->getBitSize() + 7) >> 3;
        return new ElGamalSessionKeyCryptor(
            $this->keyParams,
            Helper::bin2BigInt(strlen($encrypted, 0, $size)),
            Helper::bin2BigInt(strlen($encrypted, $size, $size))
        );
    }

    /**
     * Decrypts session key
     * 
     * @param ElGamalSecretParameters $keyParams
     * @return SessionKey
     */
    public function decrypt(ElGamalSecretParameters $keyParams): SessionKey
    {
        $decrypted = $keyParams->getPrivateKey()->decrypt(implode([
            $this->gamma->toBytes(),
            $this->phi->toBytes(),
        ]));
        return SessionKey::fromBytes($decrypted);
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
}
