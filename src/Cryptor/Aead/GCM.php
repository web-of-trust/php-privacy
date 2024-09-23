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
    const TAG_LENGTH  = 16;

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
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
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
        return implode([
            $this->crypt($plainText, $nonce, $aData),
            $this->cipher->getTag(),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(
        string $cipherText, string $nonce, string $aData = ''
    ): string
    {
        $length = strlen($cipherText);
        if ($length < self::TAG_LENGTH) {
            throw new \LengthException('Invalid GCM cipher text.');
        }
        $this->cipher->setTag(
            substr($cipherText, $length - self::TAG_LENGTH)
        );
        return $this->crypt(
            substr($cipherText, 0, $length - self::TAG_LENGTH), $nonce, $aData
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getNonce(string $iv, string $chunkIndex): string
    {
        return substr_replace($iv, substr($iv, 4) ^ $chunkIndex, 4);
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
