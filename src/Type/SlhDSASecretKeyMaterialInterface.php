<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

use OpenPGP\Enum\HashAlgorithm;
use PQCrypto\SLHDSA\{SigningKey, VerifyingKey};

/**
 * SLH-DSA secret key material interface
 *
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface SlhDSASecretKeyMaterialInterface extends KeyMaterialInterface
{
    /**
     * Get SLH-DSA signing private key
     *
     * @return SigningKey
     */
    function getSigningKey(): SigningKey;

    /**
     * Get SLH-DSA verifying key
     *
     * @return VerifyingKey
     */
    function getVerifyingKey(): VerifyingKey;

    /**
     * Sign a message and return signature
     *
     * @param HashAlgorithm $hash
     * @param string $message
     * @return string
     */
    function sign(HashAlgorithm $hash, string $message): string;
}
