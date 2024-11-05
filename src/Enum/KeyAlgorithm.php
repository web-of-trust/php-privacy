<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

use OpenPGP\Common\Config;

/**
 * Key algorithm enum
 *
 * Public Key Algorithms
 * See https://www.rfc-editor.org/rfc/rfc9580#section-9.1
 *
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum KeyAlgorithm: int
{
    /**
     * RSA (Encrypt or Sign) [HAC]
     */
    case RsaEncryptSign = 1;

    /**
     * RSA (Encrypt only) [HAC]
     */
    case RsaEncrypt = 2;

    /**
     * RSA (Sign only) [HAC]
     */
    case RsaSign = 3;

    /**
     * Elgamal (Encrypt only) [ELGAMAL] [HAC]
     */
    case ElGamal = 16;

    /**
     * DSA (Sign only) [FIPS186] [HAC]
     */
    case Dsa = 17;

    /**
     * ECDH (Encrypt only) [RFC6637]
     */
    case Ecdh = 18;

    /**
     * ECDSA (Sign only) [RFC6637]
     */
    case EcDsa = 19;

    /**
     * ECDSA (Sign only) [RFC6637]
     */
    case ElGamalEncryptSign = 20;

    /**
     * Diffie Hellman
     */
    case DiffieHellman = 21;

    /**
     * EdDSA (Sign only) - deprecated by rfc9580 (replaced by `ed25519` identifier below)
     */
    case EdDsaLegacy = 22;

    /**
     * Reserved for AEDH
     */
    case Aedh = 23;

    /**
     * Reserved for AEDSA
     */
    case AeDsa = 24;

    /**
     * X25519 (Encrypt only)
     */
    case X25519 = 25;

    /**
     * X448 (Encrypt only)
     */
    case X448 = 26;

    /**
     * Ed25519 (Sign only)
     */
    case Ed25519 = 27;

    /**
     * Ed448 (Sign only)
     */
    case Ed448 = 28;

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
            self::Aedh,
            self::X25519,
            self::X448
                => false,
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
            self::EdDsaLegacy,
            self::AeDsa,
            self::Ed25519,
            self::Ed448
                => false,
            default => true,
        };
    }

    /**
     * Get key version
     *
     * @return int
     */
    public function keyVersion(): int
    {
        return match ($this) {
            self::X25519, self::X448, self::Ed25519, self::Ed448
                => KeyVersion::V6->value,
            default => Config::useV6Key()
                ? KeyVersion::V6->value
                : KeyVersion::V4->value,
        };
    }
}
