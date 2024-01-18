<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Cryptor\Aead;

use OpenPGP\Cryptor\Mac\CMac;
use OpenPGP\Enum\SymmetricAlgorithm;
use phpseclib3\Crypt\Common\BlockCipher;

/**
 * EAX Authenticated-Encryption class
 * A Two-Pass Authenticated-Encryption Scheme Optimized for Simplicity and
 * Efficiency - by M. Bellare, P. Rogaway, D. Wagner.
 *
 * https://www.cs.ucdavis.edu/~rogaway/papers/eax.pdf
 *
 * EAX is an AEAD scheme based on CTR and OMAC1/CMAC, that uses a single block
 * cipher to encrypt and authenticate data. It's on-line (the length of a
 * message isn't needed to begin processing it), has good performances, it's
 * simple and provably secure (provided the underlying block cipher is secure).
 * 
 * @package  OpenPGP
 * @category Cryptor
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
final class EAX implements AeadCipher
{
    const N_TAG = "\x00";
    const H_TAG = "\x01";
    const C_TAG = "\x02";

    const CIPHER_MODE = 'ctr';

    private readonly BlockCipher $cipher;
    private readonly CMac $mac;

    private readonly string $zeroBlock;
    private readonly string $oneBlock;
    private readonly string $twoBlock;

    /**
     * Constructor
     *
     * @param string $key - The encryption key
     * @param SymmetricAlgorithm $symmetric - The symmetric cipher algorithm to use
     * @return self
     */
    public function __construct(
        private readonly string $key,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128
    )
    {
        $this->cipher = $symmetric->cipherEngine(self::CIPHER_MODE);
        $this->cipher->setKey($key);
        $this->mac = new CMac($symmetric);

        $tagLength = $this->mac->getMacSize();
        $this->zeroBlock = str_repeat(self::N_TAG, $tagLength);
        $this->oneBlock  = str_repeat(self::N_TAG, $tagLength - 1) . self::H_TAG;
        $this->twoBlock  = str_repeat(self::N_TAG, $tagLength - 1) . self::C_TAG;
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(
        string $plaintext, string $nonce, string $adata = ''
    ): string
    {
        $omacNonce = $this->omac($this->zeroBlock, $nonce);
        $omacAdata = $this->omac($this->oneBlock, $adata);

        $ciphered = $this->crypt($plaintext, $omacNonce);
        $omacCiphered = $this->omac($this->twoBlock, $ciphered);
        $tag = $omacCiphered ^ $omacAdata ^ $omacNonce;

        return implode([$ciphered, $tag]);
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(
        string $ciphertext, string $nonce, string $adata = ''
    ): string
    {
        $length = strlen($ciphertext);
        $tagLength = $this->mac->getMacSize();

        if ($length < $tagLength) {
            throw new \LengthException('Invalid EAX ciphertext');
        }
        $ciphered = substr($ciphertext, 0, $length - $tagLength);
        $ctTag = substr($ciphertext, $length - $tagLength);

        $omacNonce = $this->omac($this->zeroBlock, $nonce);
        $omacAdata = $this->omac($this->oneBlock, $adata);
        $omacCiphered = $this->omac($this->twoBlock, $ciphered);
        $tag = $omacCiphered ^ $omacAdata ^ $omacNonce;

        if ($ctTag !== $tag) {
            throw new \UnexpectedValueException('Authentication tag mismatch');
        }

        return $this->crypt($ciphered, $omacNonce);
    }

    /**
     * Get EAX nonce as defined by
     * {@link https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-10#section-5.16.1|RFC4880bis-10,
     * section 5.16.1}.
     * 
     * @param string $iv - The initialization vector (16 bytes)
     * @param string $chunkIndex - The chunk index (8 bytes)
     * @return string
     */
    public function getNonce(string $iv, string $chunkIndex): string
    {
        $nonce = $iv;
        for ($i = 0; $i < strlen($chunkIndex); $i++) {
            $nonce[8 + $i] = $nonce[8 + $i] ^ $chunkIndex[$i];
        }
        return $nonce;
    }

    private function omac(string $tag, string $message): string
    {
        return $this->mac->generate(
            implode([$tag, $message]), $this->key
        );
    }

    private function crypt(string $text, string $iv): string
    {
        $this->cipher->setIV($iv);
        return $this->cipher->encrypt($text);
    }
}
