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
    SessionKeyInterface
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
     * Produce session key from byte string & pkesk version
     *
     * @param string $bytes
     * @return SessionKeyInterface
     */
    public static function sessionKeyFromBytes(
        string $bytes
    ): SessionKeyInterface {
        return SessionKey::fromBytes($bytes);
    }

    /**
     * {@inheritdoc}
     */
    public function decryptSessionKey(
        SecretKeyPacketInterface $secretKey
    ): SessionKeyInterface {
        return self::sessionKeyFromBytes(
            $this->decrypt($secretKey->getKeyMaterial()->getAsymmetricKey())
        );
    }

    /**
     * Decrypt session key by using private key
     *
     * @param AsymmetricKey $privateKey
     * @return string
     */
    abstract protected function decrypt(AsymmetricKey $privateKey): string;
}
