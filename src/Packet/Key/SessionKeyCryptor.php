<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Type\{
    SecretKeyPacketInterface,
    SessionKeyCryptorInterface,
    SessionKeyInterface,
};
use phpseclib3\Crypt\Common\AsymmetricKey;

/**
 * Session key cryptor class.
 * 
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
abstract class SessionKeyCryptor implements SessionKeyCryptorInterface
{
    /**
     * Constructor
     *
     * @param int $pkeskVersion
     * @return self
     */
    protected function __construct(
        private readonly int $pkeskVersion
    )
    {
    }

    /**
     * Produce session key from byte string & pkesk version
     *
     * @param string $bytes
     * @param int $pkeskVersion
     * @return string
     */
    public static function sessionKeyFromBytes(
        string $bytes, int $pkeskVersion
    ): SessionKeyInterface
    {
        if ($pkeskVersion === self::PKESK_VERSION_3) {
            return SessionKey::fromBytes($bytes);
        }
        else {
            $sessionKey = new SessionKey(
                substr($bytes, 0, strlen($bytes) - 2)
            );

            $checksum = substr($bytes, strlen($bytes) - 2);
            if (strcmp($sessionKey->computeChecksum(), $checksum) !== 0) {
                throw new \UnexpectedValueException(
                    'Session key checksum mismatch!'
                );
            }
            return $sessionKey;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function decryptSessionKey(
        SecretKeyPacketInterface $secretKey
    ): SessionKeyInterface
    {
        return self::sessionKeyFromBytes(this->decrypt(
            $secretKey->getKeyMaterial()->getAsymmetricKey()
        ));
    }

    /**
     * Decrypt session key by using private key
     *
     * @param AsymmetricKey $privateKey
     * @return string
     */
    protected abstract function decrypt(AsymmetricKey $privateKey): string;
}
