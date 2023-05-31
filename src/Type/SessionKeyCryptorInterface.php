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
 * @package   OpenPGP
 * @category  Type
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
interface SessionKeyCryptorInterface
{
    /**
     * Decrypts session key by using secret key packet
     *
     * @param SecretKeyPacketInterface $secretKey
     * @return SessionKeyInterface
     */
    function decryptSessionKey(SecretKeyPacketInterface $secretKey): SessionKeyInterface;

    /**
     * Serializes session key material to bytes
     * 
     * @return string
     */
    function toBytes(): string;
}
