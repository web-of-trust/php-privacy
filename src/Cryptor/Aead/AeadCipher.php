<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Cryptor\Aead;

/**
 * Aead cipher interface
 * 
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface AeadCipher
{
    /**
     * Encrypt plain text input.
     *
     * @param string $plainText - The plain text input to be encrypted
     * @param string $nonce - The nonce
     * @param string $aData - Associated data to sign
     * @return string The cipher text output.
     */
    function encrypt(
        string $plainText, string $nonce, string $aData = ''
    ): string;

    /**
     * Decrypt cipher text input.
     *
     * @param string $cipherText - The cipher text input to be decrypted
     * @param string $nonce - The nonce
     * @param string $aData - Associated data to verify
     * @return string The plain text output.
     */
    function decrypt(
        string $cipherText, string $nonce, string $aData = ''
    ): string;
}
