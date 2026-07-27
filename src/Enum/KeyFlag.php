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
 * @see https://www.rfc-editor.org/rfc/rfc9580#section-5.2.3.29
 *
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum KeyFlag: string
{
    /**
     * This key may be used to make User ID certifications
     * (Signature Type IDs 0x10-0x13) or Direct Key signatures
     * (Signature Type ID 0x1F) over other keys.
     */
    case CertifyKeys = "\x01";

    /**
     * This key may be used to sign data.
     */
    case SignData = "\x02";

    /**
     * This key may be used to encrypt communications.
     */
    case EncryptCommunication = "\x04";

    /**
     * This key may be used to encrypt storage.
     */
    case EncryptStorage = "\x08";

    /**
     * The private component of this key may have been split by a secret-sharing mechanism.
     */
    case SplitPrivateKey = "\x10";

    /**
     * This key may be used for authentication.
     */
    case Authentication = "\x20";

    /**
     * The private component of this key may be in the possession of more than one person.
     */
    case SharedPrivateKey = "\x80";
}
