<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

/**
 * Key algorithm enum
 * Public-Key Algorithms
 * See https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-04#section-9.1
 *
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum KeyAlgorithm: int
{
    case RsaEncryptSign = 1;

    case RsaEncrypt = 2;

    case RsaSign = 3;

    case ElGamal = 16;

    case Dsa = 17;

    case Ecdh = 18;

    case EcDsa = 19;

    case ElgamalEncryptSign = 20;

    case DiffieHellman = 21;

    case EdDsa = 22;

    case Aedh = 23;

    case AeDsa = 24;

    /**
     * For signing
     *
     * @return bool
     */
    public function forSigning(): bool
    {
        return match ($this) {
            self::RsaEncrypt,
            self::ElGamal,
            self::Ecdh,
            self::DiffieHellman,
            self::Aedh => false,
            default => true,
        };
    }

    /**
     * For encryption
     *
     * @return bool
     */
    public function forEncryption(): bool
    {
        return match ($this) {
            self::RsaSign,
            self::Dsa,
            self::EcDsa,
            self::EdDsa,
            self::AeDsa => false,
            default => true,
        };
    }
}
