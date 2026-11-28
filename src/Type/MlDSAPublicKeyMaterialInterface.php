<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

use OpenPGP\Enum\HashAlgorithm;
use ParagonIE\PQCrypto\VerificationKeyInterface;

/**
 * ML-DSA public key material interface
 *
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface MlDSAPublicKeyMaterialInterface extends KeyMaterialInterface
{
    /**
     * Get ML-DSA verification key
     *
     * @return VerificationKeyInterface
     */
    function getVerificationKey(): VerificationKeyInterface;

    /**
     * Verify a signature with message
     *
     * @param HashAlgorithm $hash
     * @param string $message
     * @param string $signature
     * @return bool
     */
    function verify(
        HashAlgorithm $hash,
        string $message,
        string $signature,
    ): bool;
}
