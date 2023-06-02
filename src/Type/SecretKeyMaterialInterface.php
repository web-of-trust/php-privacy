<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

use phpseclib3\Crypt\Common\{
    PrivateKey,
    PublicKey,
};
use OpenPGP\Enum\HashAlgorithm;

/**
 * Secret key material interface
 * 
 * @package   OpenPGP
 * @category  Type
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
interface SecretKeyMaterialInterface extends KeyMaterialInterface
{
    /**
     * Get phpseclib3 private key
     * 
     * @return PrivateKey
     */
    function getPrivateKey(): PrivateKey;

    /**
     * Get phpseclib3 public key
     * 
     * @return PublicKey
     */
    function getPublicKey(): PublicKey;

    /**
     * Sign a message and return signature
     * 
     * @param HashAlgorithm $hash
     * @param string $message
     * @return string
     */
    function sign(HashAlgorithm $hash, string $message): string;
}
