<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

/**
 * KeyFlag enum
 *
 * @package    OpenPGP
 * @category   Enum
 * @author     Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright  Copyright © 2023-present by Nguyen Van Nguyen.
 */
enum KeyFlag: int
{
    /**
     * 0x01 - This key may be used to certify other keys.
     */
    case CertifyKeys = 1;

    /**
     * 0x02 - This key may be used to sign data.
     */
    case SignData = 2;

    /**
     * 0x04 - This key may be used to encrypt communications.
     */
    case EncryptCommunication = 4;

    /**
     * 0x08 - This key may be used to encrypt storage.
     */
    case EncryptStorage = 8;

    /**
     * 0x10 - The private component of this key may have been split by a secret-sharing mechanism.
     */
    case SplitPrivateKey = 16;

    /**
     * 0x20 - This key may be used for authentication.
     */
    case Authentication = 32;

    /**
     * 0x80 - The private component of this key may be in the possession of more than one person.
     */
    case SharedPrivateKey = 128;
}
