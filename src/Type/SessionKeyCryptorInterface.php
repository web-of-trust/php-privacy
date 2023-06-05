<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

/**
 * Session key cryptor interface
 * 
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface SessionKeyCryptorInterface
{
    /**
     * Decrypt session key by using secret key packet
     *
     * @param SecretKeyPacketInterface $secretKey
     * @return SessionKeyInterface
     */
    function decryptSessionKey(SecretKeyPacketInterface $secretKey): SessionKeyInterface;

    /**
     * Serialize session key cryptor to bytes
     * 
     * @return string
     */
    function toBytes(): string;
}
