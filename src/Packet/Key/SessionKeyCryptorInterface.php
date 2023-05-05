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

/**
 * Session key cryptor interface
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
interface SessionKeyCryptorInterface
{
    /**
     * Encrypts session key
     * 
     * @return SessionKeyCryptorInterface
     */
    function encrypt(SessionKey $sessionKey): SessionKeyCryptorInterface;

    /**
     * Serializes encrypted session key to bytes
     * 
     * @return string
     */
    function encode(): string;
}
