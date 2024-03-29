<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Cryptor\Aead;

use OpenPGP\Enum\SymmetricAlgorithm;
use phpseclib3\Crypt\Common\BlockCipher;

/**
 * GCM Authenticated-Encryption class
 * Implements the Galois/Counter mode (GCM) detailed in NIST Special Publication 800-38D.
 * 
 * @package  OpenPGP
 * @category Cryptor
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
final class GCM implements AeadCipher
{
    const CIPHER_MODE = 'gcm';

    private readonly BlockCipher $cipher;

    /**
     * Constructor
     *
     * @param string $key - The encryption key
     * @param SymmetricAlgorithm $symmetric - The symmetric cipher algorithm to use
     * @return self
     */
    public function __construct(
        string $key,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128
    )
    {
        $this->cipher = $symmetric->cipherEngine(self::CIPHER_MODE);
        $this->cipher->setKey($key);
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(
        string $plaintext, string $nonce, string $adata = ''
    ): string
    {
        $this->cipher->setNonce($nonce);
        $this->cipher->setAAD($adata);
        return $this->cipher->encrypt($plaintext);
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(
        string $ciphertext, string $nonce, string $adata = ''
    ): string
    {
        $this->cipher->setNonce($nonce);
        $this->cipher->setAAD($adata);
        return $this->cipher->decrypt($ciphertext);
    }

    /**
     * Get GCM nonce. Note: this operation is not defined by the standard.
     * A future version of the standard may define GCM mode differently,
     * hopefully under a different ID (we use Private/Experimental algorithm
     * ID 100) so that we can maintain backwards compatibility.
     * 
     * @param string $iv - The initialization vector (12 bytes)
     * @param string $chunkIndex - The chunk index (8 bytes)
     * @return string
     */
    public function getNonce(string $iv, string $chunkIndex): string
    {
        $nonce = $iv;
        for ($i = 0, $len = strlen($chunkIndex); $i < $len; $i++) {
            $nonce[4 + $i] = $nonce[4 + $i] ^ $chunkIndex[$i];
        }
        return $nonce;
    }
}
