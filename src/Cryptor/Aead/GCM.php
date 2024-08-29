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
        string $plainText, string $nonce, string $aData = ''
    ): string
    {
        return $this->crypt($plainText, $nonce, $aData);
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(
        string $cipherText, string $nonce, string $aData = ''
    ): string
    {
        return $this->crypt($cipherText, $nonce, $aData);
    }

    /**
     * {@inheritdoc}
     */
    public function getNonce(string $iv, string $chunkIndex): string
    {
        $nonce = $iv;
        for ($i = 0, $len = strlen($chunkIndex); $i < $len; $i++) {
            $nonce[4 + $i] = $nonce[4 + $i] ^ $chunkIndex[$i];
        }
        return $nonce;
    }

    private function crypt(
        string $text, string $nonce, string $aData = ''
    ): string
    {
        $this->cipher->setNonce($nonce);
        $this->cipher->setAAD($aData);
        return $this->cipher->encrypt($text);
    }
}
