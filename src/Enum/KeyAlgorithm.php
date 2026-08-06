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
enum KeyAlgorithm: string
{
    /**
     * RSA (Encrypt or Sign) [HAC]
     */
    case RsaEncryptSign = "\x01";

    /**
     * RSA (Encrypt only) [HAC]
     */
    case RsaEncrypt = "\x02";

    /**
     * RSA (Sign only) [HAC]
     */
    case RsaSign = "\x03";

    /**
     * Elgamal (Encrypt only) [ELGAMAL] [HAC]
     */
    case ElGamal = "\x10";

    /**
     * DSA (Sign only) [FIPS186] [HAC]
     */
    case Dsa = "\x11";

    /**
     * ECDH (Encrypt only) [RFC6637]
     */
    case Ecdh = "\x12";

    /**
     * ECDSA (Sign only) [RFC6637]
     */
    case EcDsa = "\x13";

    /**
     * ElGamal encrypt & sign
     */
    case ElGamalEncryptSign = "\x14";

    /**
     * Diffie Hellman
     */
    case DiffieHellman = "\x15";

    /**
     * EdDSA (Sign only) - deprecated by rfc9580 (replaced by `ed25519` identifier below)
     */
    case EdDsaLegacy = "\x16";

    /**
     * Reserved for AEDH
     */
    case Aedh = "\x17";

    /**
     * Reserved for AEDSA
     */
    case AeDsa = "\x18";

    /**
     * X25519 (Encrypt only)
     */
    case X25519 = "\x19";

    /**
     * X448 (Encrypt only)
     */
    case X448 = "\x1A";

    /**
     * Ed25519 (Sign only)
     */
    case Ed25519 = "\x1B";

    /**
     * Ed448 (Sign only)
     */
    case Ed448 = "\x1C";

    /**
     * ML-DSA-65+Ed25519 (Sign only)
     */
    case MlDsa65Ed25519 = "\x1E";

    /**
     * ML-DSA-87+Ed448 (Sign only)
     */
    case MlDsa87Ed448 = "\x1F";

    /**
     * SLH-DSA-SHAKE-128s(Sign only)
     */
    case SlhDsaShake128s = "\x20";

    /**
     * SLH-DSA-SHAKE-128f (Sign only)
     */
    case SlhDsaShake128f = "\x21";

    /**
     * SLH-DSA-SHAKE-256s (Sign only)
     */
    case SlhDsaShake256s = "\x22";

    /**
     * ML-KEM-768+X25519 (Encrypt only)
     */
    case MlKem768X25519 = "\x23";

    /**
     * ML-KEM-1024+X448 (Encrypt only)
     */
    case MlKem1024X448 = "\x24";

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
            self::X448,
            self::MlKem768X25519,
            self::MlKem1024X448
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
            self::Ed448,
            self::MlDsa65Ed25519,
            self::MlDsa87Ed448,
            self::SlhDsaShake128s,
            self::SlhDsaShake128f,
            self::SlhDsaShake256s
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
            self::X25519, self::X448, self::Ed25519, self::Ed448,
            self::MlDsa65Ed25519, self::MlDsa87Ed448, self::SlhDsaShake128s,
            self::SlhDsaShake128f, self::SlhDsaShake256s,
            self::MlKem768X25519, self::MlKem1024X448 => self::V6->value,
            default => Config::presetRFC() == PresetRFC::RFC9580
                ? KeyVersion::V6->value
                : KeyVersion::V4->value,
        };
    }
}
