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
 * KeyAlgorithm enum
 * Public-Key Algorithms
 * See https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-04#section-9.1
 *
 * @package    OpenPGP
 * @category   Enum
 * @author     Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright  Copyright © 2023-present by Nguyen Van Nguyen.
 */
enum KeyAlgorithm: int
{
    case RsaEncryptSign = 1;

    case RsaEncrypt = 2;

    case RsaSign = 3;

    case ElGamal = 16;

    case DSA = 17;

    case ECDH = 18;

    case ECDSA = 19;

    case ElgamalEncryptSign = 20;

    case DiffieHellman = 21;

    case EdDSA = 22;

    case AEDH = 23;

    case AEDSA = 24;
}
