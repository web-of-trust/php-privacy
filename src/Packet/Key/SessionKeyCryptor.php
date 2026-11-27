<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Type\{SecretKeyPacketInterface, SessionKeyCryptorInterface};
use phpseclib4\Crypt\Common\PrivateKey;

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
     * {@inheritdoc}
     */
    public function decryptSessionKey(
        SecretKeyPacketInterface $secretKey,
    ): string {
        return $this->decrypt($secretKey->getKeyMaterial()->getPrivateKey());
    }

    /**
     * Decrypt session key by using private key
     *
     * @param PrivateKey $privateKey
     * @return string
     */
    abstract protected function decrypt(PrivateKey $privateKey): string;
}
