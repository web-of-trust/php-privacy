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

use phpseclib3\Crypt\Common\AsymmetricKey;

/**
 * Key material interface
 * 
 * @package   OpenPGP
 * @category  Type
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
interface KeyMaterialInterface
{
    /**
     * Gets public key material
     * 
     * @return KeyMaterialInterface
     */
    function getPublicMaterial(): KeyMaterialInterface;

    /**
     * Gets asymmetric key
     * 
     * @return AsymmetricKey
     */
    function getAsymmetricKey(): AsymmetricKey;

    /**
     * Gets key material parameters
     * 
     * @return array<mixed>
     */
    function getParameters(): array;

    /**
     * Returns key material is valid
     * 
     * @return bool
     */
    function isValid(): bool;

    /**
     * Serializes key material to bytes
     * 
     * @return string
     */
    function toBytes(): string;
}
