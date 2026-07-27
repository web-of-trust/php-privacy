<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

use phpseclib4\Crypt\EC\BaseCurves\Base as BaseCurve;
use phpseclib4\Crypt\EC\Curves\{
    secp256r1,
    secp384r1,
    secp521r1,
    brainpoolP256r1,
    brainpoolP384r1,
    brainpoolP512r1,
    Ed25519,
    Curve25519,
};
use phpseclib4\File\ASN1;

/**
 * Elliptic curve cryptography enum
 *
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum Ecc: string
{
    /**
     * oid: 1.2.840.10045.3.1.7
     */
    case Secp256r1 = "\x2A\x86\x48\xCE\x3D\x03\x01\x07";

    /**
     * oid: 1.3.132.0.34
     */
    case Secp384r1 = "\x2B\x81\x04\x00\x22";

    /**
     * oid: 1.3.132.0.35
     */
    case Secp521r1 = "\x2B\x81\x04\x00\x23";

    /**
     * oid: 1.3.36.3.3.2.8.1.1.7
     */
    case BrainpoolP256r1 = "\x2B\x24\x03\x03\x02\x08\x01\x01\x07";

    /**
     * oid: 1.3.36.3.3.2.8.1.1.11
     */
    case BrainpoolP384r1 = "\x2B\x24\x03\x03\x02\x08\x01\x01\x0B";

    /**
     * oid: 1.3.36.3.3.2.8.1.1.13
     */
    case BrainpoolP512r1 = "\x2B\x24\x03\x03\x02\x08\x01\x01\x0D";

    /**
     * oid: 1.3.6.1.4.1.11591.15.1
     */
    case Ed25519 = "\x2B\x06\x01\x04\x01\xDA\x47\x0F\x01";

    /**
     * oid: 1.3.6.1.4.1.3029.1.5.1
     */
    case Curve25519 = "\x2B\x06\x01\x04\x01\x97\x55\x01\x05\x01";

    /**
     * Get curve
     *
     * @return BaseCurve
     */
    public function getCurve(): BaseCurve
    {
        return match ($this) {
            self::Secp256r1 => new secp256r1(),
            self::Secp384r1 => new secp384r1(),
            self::Secp521r1 => new secp521r1(),
            self::BrainpoolP256r1 => new brainpoolP256r1(),
            self::BrainpoolP384r1 => new brainpoolP384r1(),
            self::BrainpoolP512r1 => new brainpoolP512r1(),
            self::Ed25519 => new Ed25519(),
            self::Curve25519 => new Curve25519(),
        };
    }

    /**
     * Get hash algorithm
     *
     * @return HashAlgorithm
     */
    public function hashAlgorithm(): HashAlgorithm
    {
        return match ($this) {
            self::Secp256r1,
            self::BrainpoolP256r1,
            self::Curve25519
                => HashAlgorithm::Sha256,
            self::Secp384r1, self::BrainpoolP384r1 => HashAlgorithm::Sha384,
            self::Secp521r1,
            self::BrainpoolP512r1,
            self::Ed25519
                => HashAlgorithm::Sha512,
        };
    }

    /**
     * Get symmetric algorithm
     *
     * @return SymmetricAlgorithm
     */
    public function symmetricAlgorithm(): SymmetricAlgorithm
    {
        return match ($this) {
            self::Secp256r1,
            self::BrainpoolP256r1,
            self::Ed25519,
            self::Curve25519
                => SymmetricAlgorithm::Aes128,
            self::Secp384r1,
            self::BrainpoolP384r1
                => SymmetricAlgorithm::Aes192,
            self::Secp521r1,
            self::BrainpoolP512r1
                => SymmetricAlgorithm::Aes256,
        };
    }
}
