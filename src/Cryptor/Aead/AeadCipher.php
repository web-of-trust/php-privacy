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
     * Encrypt plaintext input.
     *
     * @param string $plaintext - The cleartext input to be encrypted
     * @param string $nonce - The nonce
     * @param string $adata - Associated data to sign
     * @return string The ciphertext output.
     */
    function encrypt(
        string $plaintext, string $nonce, string $adata = ''
    ): string;

    /**
     * Decrypt ciphertext input.
     *
     * @param string $ciphertext - The ciphertext input to be decrypted
     * @param string $nonce - The nonce
     * @param string $adata - Associated data to verify
     * @return string The plaintext output.
     */
    function decrypt(
        string $ciphertext, string $nonce, string $adata = ''
    ): string;
}
