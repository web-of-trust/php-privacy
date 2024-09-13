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
     * {@inheritdoc}
     */
    public function decryptSessionKey(
        SecretKeyPacketInterface $secretKey
    ): SessionKeyInterface
    {
        $decrypted = $this->decrypt(
            $secretKey->getKeyMaterial()->getAsymmetricKey()
        );
        return $this->pkeskVersion === self::PKESK_VERSION_3 ?
            SessionKey::fromBytes($decrypted) :
            new SessionKey($decrypted);
    }

    /**
     * Decrypt session key by using private key
     *
     * @param AsymmetricKey $privateKey
     * @return string
     */
    protected abstract function decrypt(AsymmetricKey $privateKey): string;
}
