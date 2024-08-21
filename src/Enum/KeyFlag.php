<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

/**
 * Key flag enum
 * 
 * @see https://www.rfc-editor.org/rfc/rfc9580#name-key-flags
 *
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum KeyFlag: int
{
    /**
     * This key may be used to make User ID certifications
     * (Signature Type IDs 0x10-0x13) or Direct Key signatures
     * (Signature Type ID 0x1F) over other keys.
     */
    case CertifyKeys = 0x01;

    /**
     * This key may be used to sign data.
     */
    case SignData = 0x02;

    /**
     * This key may be used to encrypt communications.
     */
    case EncryptCommunication = 0x04;

    /**
     * This key may be used to encrypt storage.
     */
    case EncryptStorage = 0x08;

    /**
     * The private component of this key may have been split by a secret-sharing mechanism.
     */
    case SplitPrivateKey = 0x10;

    /**
     * This key may be used for authentication.
     */
    case Authentication = 0x20;

    /**
     * The private component of this key may be in the possession of more than one person.
     */
    case SharedPrivateKey = 0x80;
}
