<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Cryptor\Symmetric;

/**
 * Ecb symmetric cipher interface
 *
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface EcbCipher
{
    /**
     * Encrypts a block
     *
     * @param string $in
     * @return string
     */
    function encryptBlock($in): string;

    /**
     * Decrypts a block
     *
     * @param string $in
     * @return string
     */
    function decryptBlock($in): string;

    /**
     * Sets the key.
     *
     * @param string $key
     */
    function setKey($key);
}
