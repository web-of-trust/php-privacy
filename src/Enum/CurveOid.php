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

use phpseclib3\Crypt\EC\BaseCurves\Base as BaseCurve;
use phpseclib3\Crypt\EC\Curves\{
    prime256v1,
    secp256k1,
    secp384r1,
    secp521r1,
    brainpoolP256r1,
    brainpoolP384r1,
    brainpoolP512r1,
    Ed25519,
    Curve25519,
};

/**
 * Curve oid enum
 *
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum CurveOid: string
{
    case Prime256v1 = '1.2.840.10045.3.1.7';

    case Secp256k1 = '1.3.132.0.10';

    case Secp384r1 = '1.3.132.0.34';

    case Secp521r1 = '1.3.132.0.35';

    case BrainpoolP256r1 = '1.3.36.3.3.2.8.1.1.7';

    case BrainpoolP384r1 = '1.3.36.3.3.2.8.1.1.11';

    case BrainpoolP512r1 = '1.3.36.3.3.2.8.1.1.13';

    case Ed25519 = '1.3.6.1.4.1.11591.15.1';

    case Curve25519 = '1.3.6.1.4.1.3029.1.5.1';

    public function getCurve(): BaseCurve
    {
        return match($this) {
            self::Prime256v1 => new prime256v1(),
            self::Secp256k1 => new secp256k1(),
            self::Secp384r1 => new secp384r1,
            self::Secp521r1 => new secp521r1(),
            self::BrainpoolP256r1 => new brainpoolP256r1(),
            self::BrainpoolP384r1 => new brainpoolP384r1(),
            self::BrainpoolP512r1 => new brainpoolP512r1(),
            self::Ed25519 => new Ed25519(),
            self::Curve25519 => new Curve25519(),
        };
    }

    public function hashAlgorithm(): HashAlgorithm
    {
        return match($this) {
            self::Prime256v1 => HashAlgorithm::Sha256,
            self::Secp256k1 => HashAlgorithm::Sha256,
            self::Secp384r1 => HashAlgorithm::Sha384,
            self::Secp521r1 => HashAlgorithm::Sha512,
            self::BrainpoolP256r1 => HashAlgorithm::Sha256,
            self::BrainpoolP384r1 => HashAlgorithm::Sha384,
            self::BrainpoolP512r1 => HashAlgorithm::Sha512,
            self::Ed25519 => HashAlgorithm::Sha512,
            self::Curve25519 => HashAlgorithm::Sha256,
        };
    }

    public function symmetricAlgorithm(): SymmetricAlgorithm
    {
        return match($this) {
            self::Prime256v1 => SymmetricAlgorithm::Aes128,
            self::Secp256k1 => SymmetricAlgorithm::Aes128,
            self::Secp384r1 => SymmetricAlgorithm::Aes128,
            self::Secp521r1 => SymmetricAlgorithm::Aes256,
            self::BrainpoolP256r1 => SymmetricAlgorithm::Aes192,
            self::BrainpoolP384r1 => SymmetricAlgorithm::Aes192,
            self::BrainpoolP512r1 => SymmetricAlgorithm::Aes256,
            self::Ed25519 => SymmetricAlgorithm::Aes128,
            self::Curve25519 => SymmetricAlgorithm::Aes128,
        };
    }
}
