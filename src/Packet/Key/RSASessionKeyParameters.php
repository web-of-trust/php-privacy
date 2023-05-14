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
use phpseclib3\Crypt\RSA\{PrivateKey, PublicKey};
use phpseclib3\Math\BigInteger;
use OpenPGP\Common\Helper;

/**
 * RSASessionKeyParameters class.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class RSASessionKeyParameters implements SessionKeyParametersInterface
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
     * Reads encrypted session key from byte string
     *
     * @param string $bytes
     * @return RSASessionKeyParameters
     */
    public static function fromBytes(string $bytes): RSASessionKeyParameters
    {
        return new RSASessionKeyParameters(Helper::readMPI($bytes));
    }

    /**
     * Produces parameters by encrypting session key
     *
     * @param SessionKey $sessionKey
     * @param PublicKey $publicKey
     * @return RSASessionKeyParameters
     */
    public static function produceParameters(
        SessionKey $sessionKey, PublicKey $publicKey
    ): RSASessionKeyParameters
    {
        $publicKey = $publicKey->withPadding(RSA::ENCRYPTION_PKCS1);
        return new RSASessionKeyParameters(
            Helper::bin2BigInt($publicKey->encrypt(implode([
                $sessionKey->encode(),
                $sessionKey->computeChecksum(),
            ])))
        );
    }

    /**
     * {@inheritdoc}
     */
    public function encode(): string
    {
        return implode([
            pack('n', $this->encrypted->getLength()),
            $this->encrypted->toBytes(),
        ]);
    }

    /**
     * Gets encrypted session key
     *
     * @return BigInteger
     */
    public function getEncrypted(): BigInteger
    {
        return $this->encrypted;
    }

    /**
     * Decrypts session key by using private key
     *
     * @param PrivateKey $privateKey
     * @return SessionKey
     */
    public function decrypt(PrivateKey $privateKey): SessionKey
    {
        $privateKey = $privateKey->withPadding(RSA::ENCRYPTION_PKCS1);
        return SessionKey::fromBytes($privateKey->decrypt(
            $this->encrypted->toBytes()
        ));
    }
}
