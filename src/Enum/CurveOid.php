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
use phpseclib3\Crypt\EC\Curves{
    prime256v1,
    secp256k1,
    secp384r1,
    secp521r1,
    brainpoolP256r1,
    brainpoolP384r1,
    brainpoolP512r1,
    ed25519,
    curve25519
};


/**
 * CurveOid enum
 *
 * @package    OpenPGP
 * @category   Enum
 * @author     Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright  Copyright © 2023-present by Nguyen Van Nguyen.
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
            CurveInfo::Prime256v1 => new prime256v1(),
            CurveInfo::Secp256k1 => new secp256k1(),
            CurveInfo::Secp384r1 => new secp384r1,
            CurveInfo::Secp521r1 => new secp521r1(),
            CurveInfo::BrainpoolP256r1 => new brainpoolP256r1(),
            CurveInfo::BrainpoolP384r1 => new brainpoolP384r1(),
            CurveInfo::BrainpoolP512r1 => brainpoolP512r1(),
            CurveInfo::Ed25519 => new ed25519(),
            CurveInfo::Curve25519 => new curve25519(),
        };
    }

    public function fieldSize(): int
    {
        return match($this) {
            CurveInfo::Prime256v1 => 256,
            CurveInfo::Secp256k1 => 256,
            CurveInfo::Secp384r1 => 384,
            CurveInfo::Secp521r1 => 521,
            CurveInfo::BrainpoolP256r1 => 256,
            CurveInfo::BrainpoolP384r1 => 384,
            CurveInfo::BrainpoolP512r1 => 512,
            CurveInfo::Ed25519 => 255,
            CurveInfo::Curve25519 => 255,
        };
    }

    public function hashAlgorithm(): HashAlgorithm
    {
        return match($this) {
            CurveInfo::Prime256v1 => HashAlgorithm::SHA256,
            CurveInfo::Secp256k1 => HashAlgorithm::SHA256,
            CurveInfo::Secp384r1 => HashAlgorithm::SHA384,
            CurveInfo::Secp521r1 => HashAlgorithm::SHA512,
            CurveInfo::BrainpoolP256r1 => HashAlgorithm::SHA256,
            CurveInfo::BrainpoolP384r1 => HashAlgorithm::SHA384,
            CurveInfo::BrainpoolP512r1 => HashAlgorithm::SHA512,
            CurveInfo::Ed25519 => HashAlgorithm::SHA256,
            CurveInfo::Curve25519 => HashAlgorithm::SHA256,
        };
    }

    public function symmetricAlgorithm(): SymmetricAlgorithm
    {
        return match($this) {
            CurveInfo::Prime256v1 => SymmetricAlgorithm::Aes128,
            CurveInfo::Secp256k1 => SymmetricAlgorithm::Aes128,
            CurveInfo::Secp384r1 => SymmetricAlgorithm::Aes128,
            CurveInfo::Secp521r1 => SymmetricAlgorithm::Aes256,
            CurveInfo::BrainpoolP256r1 => SymmetricAlgorithm::Aes192,
            CurveInfo::BrainpoolP384r1 => SymmetricAlgorithm::Aes192,
            CurveInfo::BrainpoolP512r1 => SymmetricAlgorithm::Aes256,
            CurveInfo::Ed25519 => SymmetricAlgorithm::Aes128,
            CurveInfo::Curve25519 => SymmetricAlgorithm::Aes128,
        };
    }
}
